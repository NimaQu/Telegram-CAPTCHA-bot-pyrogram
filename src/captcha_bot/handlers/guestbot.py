"""拦截群外 guest bot：有人 @ 不在群里的 bot 让它代发消息(Bot API 10.0 Guest Mode)时，
删除 bot 的回复、封禁召唤者，同时尝试封禁该 bot。

Bot 需要在 BotFather 打开 Bot-to-Bot Communication Mode 并且是群管理员，才能收到 guest bot 的回复。
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from functools import partial

from pyrogram import Client, filters
from pyrogram.enums import ParseMode
from pyrogram.errors import ChatAdminRequired, RPCError
from pyrogram.handlers import MessageHandler
from pyrogram.types import Chat, Message, User

from captcha_bot.context import AppContext
from captcha_bot.handlers.common import ChatUnavailable, fetch_member_rights, schedule, send_log

logger = logging.getLogger(__name__)

# 一条消息最多召唤 3 个 guest bot，同一召唤者短时间内只处置一次
HANDLED_SECONDS = 300
NOTICE_DELETE_SECONDS = 60
LOG_TEXT_LIMIT = 300


@dataclass(slots=True)
class GuestBotState:
    handled: dict[tuple[int, int], float] = field(default_factory=dict)

    def first_time(self, chat_id: int, caller_id: int, *, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        self.handled = {key: at for key, at in self.handled.items() if current - at < HANDLED_SECONDS}
        key = (chat_id, caller_id)
        if key in self.handled:
            return False
        self.handled[key] = current
        return True


def _is_guest_reply(_filter: object, _client: Client, message: Message) -> bool:
    return message.guest_bot_caller_user is not None or message.guest_bot_caller_chat is not None


guest_reply = filters.create(_is_guest_reply, "GuestReply")


def _name(user: User | None, chat: Chat | None) -> str:
    if user is not None:
        name = " ".join(part for part in (user.first_name, user.last_name) if part) or str(user.id)
        username = f" @{user.username}" if user.username else ""
        return f"{name}{username} ({user.id})"
    if chat is not None:
        username = f" @{chat.username}" if chat.username else ""
        return f"{chat.title or chat.id}{username} ({chat.id})"
    return "未知"


async def _caller_exempt(client: Client, chat_id: int, user: User | None, chat: Chat | None) -> bool:
    """管理员、匿名管理员和本群关联频道召唤的不处理。"""
    if chat is not None:
        if chat.id == chat_id:
            return True
        try:
            group = await client.get_chat(chat_id)
        except RPCError:
            return False
        linked = group.linked_chat
        return linked is not None and linked.id == chat.id
    if user is None:
        return True
    try:
        return (await fetch_member_rights(client, chat_id, user.id)).is_admin
    except ChatUnavailable, RPCError:
        return False


async def _ban(client: Client, chat_id: int, target_id: int) -> str | None:
    try:
        await client.ban_chat_member(chat_id, target_id)
        return None
    except ChatAdminRequired:
        return "Bot 无权封禁"
    except RPCError as exc:
        return f"封禁失败 ({exc.ID or type(exc).__name__})"


async def block_guest_reply(context: AppContext, state: GuestBotState, client: Client, message: Message) -> None:
    if message.chat is None or message.chat.id is None:
        return
    chat_id = message.chat.id
    policy = await context.policies.get(chat_id)
    if not policy.block_guest_bots:
        return
    caller_user = message.guest_bot_caller_user
    caller_chat = message.guest_bot_caller_chat
    caller_id = caller_user.id if caller_user is not None else caller_chat.id if caller_chat is not None else None
    if caller_id is None or await _caller_exempt(client, chat_id, caller_user, caller_chat):
        return
    bot = message.from_user
    try:
        await message.delete()
        deleted = True
    except RPCError:
        logger.info("failed to delete guest bot reply", extra={"chat_id": chat_id})
        deleted = False
    if not state.first_time(chat_id, caller_id):
        # 同一次召唤的其他 bot 回复，召唤者已经处置过了，只封 bot
        if bot is not None:
            await _ban(client, chat_id, bot.id)
        return
    caller_error = await _ban(client, chat_id, caller_id)
    bot_error = await _ban(client, chat_id, bot.id) if bot is not None else "未知 bot"
    chat_title = message.chat.title or str(chat_id)
    text = message.text or message.caption or ""
    content = text if len(text) <= LOG_TEXT_LIMIT else f"{text[:LOG_TEXT_LIMIT]}…"
    await send_log(
        context,
        f"#GUEST_BOT\n群组: {chat_title} ({chat_id})\n"
        f"召唤者: {_name(caller_user, caller_chat)}\n处置: {caller_error or '已封禁'}\n"
        f"Bot: {_name(bot, None)}\n处置: {'已删除回复' if deleted else '删除回复失败'}，{bot_error or '已封禁'}\n"
        f"内容: {content or '(无文字)'}",
        plain=True,
    )
    if caller_error is not None:
        return
    try:
        notice = await client.send_message(
            chat_id,
            f"已封禁 {_name(caller_user, caller_chat)}：召唤群外 bot 发送消息。",
            parse_mode=ParseMode.DISABLED,
        )
        schedule(notice.delete(), delay=NOTICE_DELETE_SECONDS, name=f"delete-guest-bot-notice:{notice.id}")
    except RPCError:
        logger.info("failed to send guest bot notice", extra={"chat_id": chat_id})


def register_guest_bot_handlers(client: Client, context: AppContext) -> None:
    # 独立分组，不和 0 组里的命令处理互相抢
    client.add_handler(
        MessageHandler(partial(block_guest_reply, context, GuestBotState()), filters.group & guest_reply), group=-2
    )
