from __future__ import annotations

import logging
from functools import partial
from urllib.parse import urlencode

from pyrogram import Client, filters
from pyrogram.errors import RPCError
from pyrogram.handlers import MessageHandler
from pyrogram.types import (
    ChatAdministratorRights,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    KeyboardButton,
    KeyboardButtonRequestChat,
    Message,
    ReplyKeyboardMarkup,
    WebAppInfo,
)

from captcha_bot.context import AppContext
from captcha_bot.handlers.common import ChatUnavailable, fetch_member_rights, is_bot_admin, schedule

logger = logging.getLogger(__name__)

CONFIG_START_PREFIX = "config_"
CHAT_PICKER_BUTTON_ID = 1
REQUIRED_ADMIN_RIGHTS = "需要该群的管理员权限，且至少拥有「删除消息」和「封禁/限制用户」。"


def miniapp_keyboard(context: AppContext, chat_id: int) -> InlineKeyboardMarkup:
    url = f"{context.config.settings.miniapp_url}?{urlencode({'chat_id': chat_id})}"
    return InlineKeyboardMarkup([[InlineKeyboardButton("打开配置面板", web_app=WebAppInfo(url=url))]])


def admin_panel_keyboard(context: AppContext) -> InlineKeyboardMarkup:
    url = f"{context.config.settings.miniapp_url}?{urlencode({'view': 'admin'})}"
    return InlineKeyboardMarkup([[InlineKeyboardButton("打开管理面板", web_app=WebAppInfo(url=url))]])


def chat_picker_keyboard() -> ReplyKeyboardMarkup:
    # Telegram 客户端只会列出用户拥有这些权限、且 Bot 已在其中的群组；服务端仍会实时复核
    rights = ChatAdministratorRights(can_manage_chat=False, can_delete_messages=True, can_restrict_members=True)
    button = KeyboardButton(
        "选择要配置的群组",
        request_chat=KeyboardButtonRequestChat(
            button_id=CHAT_PICKER_BUTTON_ID,
            chat_is_channel=False,
            bot_is_member=True,
            user_administrator_rights=rights,
        ),
    )
    return ReplyKeyboardMarkup([[button]], resize_keyboard=True, one_time_keyboard=True)


def parse_config_start(payload: str) -> int | None:
    if not payload.startswith(CONFIG_START_PREFIX):
        return None
    try:
        chat_id = int(payload.removeprefix(CONFIG_START_PREFIX))
    except ValueError:
        return None
    return chat_id if chat_id < 0 else None


async def send_miniapp_entry(context: AppContext, message: Message, chat_id: int, title: str | None = None) -> None:
    name = f"「{title}」" if title else f"`{chat_id}`"
    await message.reply(
        f"点击下方按钮打开群组 {name} 的配置面板。\n{REQUIRED_ADMIN_RIGHTS}",
        reply_markup=miniapp_keyboard(context, chat_id),
    )


async def group_config_command(context: AppContext, client: Client, message: Message) -> None:
    if message.chat is None or message.chat.id is None:
        return
    chat_id = message.chat.id
    schedule(message.delete(), delay=60, name=f"delete-config-command:{message.id}")
    if message.from_user is None:
        reply = await message.reply("请关闭匿名管理员后再使用 /config。")
        schedule(reply.delete(), delay=15, name=f"delete-config-reply:{reply.id}")
        return
    try:
        rights = await fetch_member_rights(client, chat_id, message.from_user.id)
    except ChatUnavailable, RPCError:
        logger.exception("failed to check config permission", extra={"chat_id": chat_id})
        rights = None
    if rights is None or not rights.can_configure:
        reply = await message.reply(f"{context.config.settings.messages.permission_denied}\n{REQUIRED_ADMIN_RIGHTS}")
        schedule(reply.delete(), delay=15, name=f"delete-config-reply:{reply.id}")
        return
    # Mini App 的 web_app 按钮只能在私聊中使用，所以先跳转到 Bot 私聊
    link = f"https://t.me/{context.config.settings.bot.username}?start={CONFIG_START_PREFIX}{chat_id}"
    reply = await message.reply(
        "请在私聊中打开配置面板：",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("前往配置", url=link)]]),
    )
    schedule(reply.delete(), delay=60, name=f"delete-config-reply:{reply.id}")


async def private_config_command(_context: AppContext, _client: Client, message: Message) -> None:
    await message.reply(
        "请点击下方按钮选择要配置的群组。\n"
        "列表中只会出现您拥有「删除消息」和「封禁/限制用户」权限、且本 Bot 已加入的群组。",
        reply_markup=chat_picker_keyboard(),
    )


async def admin_panel_command(context: AppContext, _client: Client, message: Message) -> None:
    if message.from_user is None or not is_bot_admin(context, message.from_user.id):
        return
    await message.reply("点击下方按钮打开 Bot 管理面板。", reply_markup=admin_panel_keyboard(context))


async def chat_shared(context: AppContext, _client: Client, message: Message) -> None:
    shared = message.chat_shared
    if shared is None or shared.button_id != CHAT_PICKER_BUTTON_ID or shared.chat is None or shared.chat.id is None:
        return
    await send_miniapp_entry(context, message, shared.chat.id, shared.chat.title)


def register_config_handlers(client: Client, context: AppContext) -> None:
    handlers = [
        (group_config_command, filters.command("config") & filters.group),
        (private_config_command, filters.command("config") & filters.private),
        (admin_panel_command, filters.command("admin") & filters.private),
        (chat_shared, filters.chat_shared & filters.private),
    ]
    for callback, handler_filter in handlers:
        client.add_handler(MessageHandler(partial(callback, context), handler_filter))
