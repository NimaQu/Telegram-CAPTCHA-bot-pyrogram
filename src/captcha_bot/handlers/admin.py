from __future__ import annotations

import logging
from datetime import timedelta
from functools import partial

from pyrogram import Client, filters
from pyrogram.enums import ChatMemberStatus
from pyrogram.enums.chat_members_filter import ChatMembersFilter
from pyrogram.errors import BadRequest, RPCError
from pyrogram.handlers import MessageHandler
from pyrogram.types import (
    LinkPreviewOptions,
    Message,
    MessageOriginHiddenUser,
    MessageOriginUser,
)

from captcha_bot import admin_ops
from captcha_bot.context import AppContext
from captcha_bot.db.repository import LogRecord
from captcha_bot.handlers.common import (
    ChatUnavailable,
    extract_message_ids,
    fetch_member_rights,
    is_bot_admin,
    schedule,
)

logger = logging.getLogger(__name__)

NO_LINK_PREVIEW = LinkPreviewOptions(is_disabled=True)


async def format_logs(context: AppContext, logs: list[LogRecord]) -> str:
    return "\n".join([record.format(await context.geoip.format(record.ip_addr)) for record in logs])


async def reload_config(context: AppContext, _client: Client, message: Message) -> None:
    if message.from_user is None or not is_bot_admin(context, message.from_user.id):
        return
    try:
        await context.config.reload()
    except (OSError, ValueError) as exc:
        await message.reply(f"配置重载失败：{exc}")
        return
    await message.reply("配置已成功重载。")


async def help_command(context: AppContext, client: Client, message: Message) -> None:
    # 匿名管理员以群身份发言，from_user 为空
    if message.from_user is not None and message.chat is not None and message.chat.id is not None:
        try:
            allowed = (await fetch_member_rights(client, message.chat.id, message.from_user.id)).can_configure
        except ChatUnavailable, RPCError:
            allowed = False
        if not allowed:
            reply = await message.reply("该命令需要群组管理员权限：删除消息、封禁/限制用户")
            schedule(reply.delete(), delay=3, name=f"delete-help-reply:{reply.id}")
            schedule(message.delete(), delay=3, name=f"delete-help-command:{message.id}")
            return
    await message.reply(context.config.settings.messages.self_introduction, link_preview_options=NO_LINK_PREVIEW)


async def ping_command(_context: AppContext, _client: Client, message: Message) -> None:
    await message.reply("poi~")


async def call_admin(context: AppContext, client: Client, message: Message) -> None:
    if message.chat is None:
        return
    chat_id = message.chat.id
    if chat_id is None:
        return
    mentions: list[str] = []
    me = await client.get_me()
    async for member in client.get_chat_members(chat_id, filter=ChatMembersFilter.ADMINISTRATORS):
        privileges = member.privileges
        if member.user.id == me.id or member.user.is_bot:
            continue
        if member.status != ChatMemberStatus.OWNER and not (
            privileges and privileges.can_restrict_members and privileges.can_delete_messages
        ):
            continue
        mentions.append(member.user.mention("admin"))
    if not mentions:
        await message.reply("没有找到可用的管理员")
        return
    reply = await message.reply(" ".join(mentions))
    schedule(reply.delete(), delay=300, name=f"delete-admin-call:{reply.id}")


async def clean_database(context: AppContext, client: Client, message: Message) -> None:
    if message.from_user is None or not is_bot_admin(context, message.from_user.id):
        return
    user_ids = await context.repository.all_blacklist_user_ids()
    await message.reply(f"开始整理数据库，请稍等...\n预计需要时间:{timedelta(seconds=len(user_ids) // 4)}")
    result = await admin_ops.clean_deleted_users(context)
    await message.reply(f"已成功清除{len(result.deleted)}个已经删号的用户，共有{result.failures}个用户信息获取失败。")


async def sender_command(_context: AppContext, client: Client, message: Message) -> None:
    if not message.command or len(message.command) != 2:
        await message.reply("使用方法: /sender [message link]")
        return
    link = message.command[1]
    if not link.startswith("https://t.me/"):
        await message.reply("链接格式错误")
        return
    try:
        chat_id, message_id = extract_message_ids(link)
        found = await client.get_messages(chat_id, message_id)
    except BadRequest:
        await message.reply("Bot 不在该群组中")
        return
    except ValueError, IndexError:
        await message.reply("链接格式错误")
        return
    except RPCError as exc:
        logger.exception("failed to retrieve Telegram message")
        await message.reply(f"获取消息失败: {exc}")
        return
    if found is None:
        await message.reply("未找到消息")
        return
    if not isinstance(found, Message):
        found = found[0]
    if found.from_user is None:
        await message.reply("未找到消息发送者")
        return
    await message.reply(found.from_user.mention(str(found.from_user.id)))


async def forwarded_user_record(context: AppContext, _client: Client, message: Message) -> None:
    if message.from_user is None or not is_bot_admin(context, message.from_user.id):
        return
    origin = message.forward_origin
    if isinstance(origin, MessageOriginHiddenUser):
        await message.reply("该用户关闭了消息转发权限，无法获取用户 ID")
        return
    if not isinstance(origin, MessageOriginUser) or origin.sender_user is None:
        await message.reply("该消息来自频道或群组的匿名身份，无法查询")
        return
    logs = await context.repository.logs_by_user(origin.sender_user.id)
    await message.reply(await format_logs(context, logs) if logs else "没有找到相关记录")


def register_admin_handlers(client: Client, context: AppContext) -> None:
    handlers = [
        (reload_config, filters.command("reload") & filters.private),
        (help_command, filters.command("help") & filters.group),
        (ping_command, filters.command("ping") & filters.private),
        (call_admin, filters.command("admin", prefixes="@") & filters.group),
        (clean_database, filters.command("clean") & filters.private),
        (sender_command, filters.command("sender") & filters.private),
        (forwarded_user_record, filters.forwarded & filters.private),
    ]
    for callback, handler_filter in handlers:
        client.add_handler(MessageHandler(partial(callback, context), handler_filter))
