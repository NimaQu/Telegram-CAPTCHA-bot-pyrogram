from __future__ import annotations

import logging
from collections import defaultdict
from datetime import timedelta
from functools import partial

from pyrogram import Client, filters
from pyrogram.enums import ChatMemberStatus
from pyrogram.enums.chat_members_filter import ChatMembersFilter
from pyrogram.errors import BadRequest, ChatAdminRequired, RPCError
from pyrogram.handlers import MessageHandler
from pyrogram.types import Message, User

from captcha_bot.context import AppContext
from captcha_bot.handlers.common import (
    can_restrict_members,
    extract_message_ids,
    is_bot_admin,
    schedule,
    send_log,
    split_long_message,
    valid_ip,
)

logger = logging.getLogger(__name__)


async def reload_config(context: AppContext, _client: Client, message: Message) -> None:
    if message.from_user is None or not is_bot_admin(context, message.from_user.id):
        return
    try:
        await context.config.reload()
    except (OSError, ValueError) as exc:
        await message.reply(f"配置重载失败：{exc}")
        return
    await message.reply("配置已成功重载。")


async def help_command(context: AppContext, _client: Client, message: Message) -> None:
    await message.reply(context.config.settings.messages.self_introduction, disable_web_page_preview=True)


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


async def leave_command(context: AppContext, client: Client, message: Message) -> None:
    if message.from_user is None or not is_bot_admin(context, message.from_user.id) or not message.text:
        return
    arguments = message.text.split()
    if len(arguments) != 2:
        await message.reply("使用方法: /leave [group_id]")
        return
    try:
        chat_id = int(arguments[1])
        await client.send_message(chat_id, context.config.settings.messages.leave_message)
        await client.leave_chat(chat_id, delete=True)
    except ValueError, RPCError:
        await message.reply("指令出错了！可能是 bot 不在参数所在群里。")
        return
    await message.reply(f"已离开群组: `{chat_id}`")
    await send_log(context, context.config.settings.messages.leave_group.format(groupid=chat_id))


async def clean_database(context: AppContext, client: Client, message: Message) -> None:
    if message.from_user is None or not is_bot_admin(context, message.from_user.id):
        return
    user_ids = await context.repository.all_blacklist_user_ids()
    await message.reply(f"开始整理数据库，请稍等...\n预计需要时间:{timedelta(seconds=len(user_ids) // 4)}")
    deleted: list[int] = []
    failures = 0
    for user_id in user_ids:
        try:
            user = await client.get_users(user_id)
        except BadRequest, IndexError:
            failures += 1
            deleted.append(user_id)
            continue
        if not isinstance(user, User):
            user = user[0]
        if user.is_deleted:
            deleted.append(user_id)
    await context.repository.remove_blacklist_users(deleted)
    await message.reply(f"已成功清除{len(deleted)}个已经删号的用户，共有{failures}个用户信息获取失败。")


async def set_config(context: AppContext, client: Client, message: Message) -> None:
    if message.from_user is None or message.chat is None or not message.text:
        await message.reply("请从个人账号发送指令。")
        return
    chat_id = message.chat.id
    if chat_id is None:
        return
    if not await can_restrict_members(client, chat_id, message.from_user.id):
        reply = await message.reply(context.config.settings.messages.permission_denied)
        schedule(reply.delete(), delay=5, name=f"delete-permission:{reply.id}")
        schedule(message.delete(), delay=5, name=f"delete-command:{message.id}")
        return
    arguments = message.text.split(maxsplit=2)
    if len(arguments) != 3:
        await message.reply(
            "使用方法:\n/faset [配置项] [值]\n\n"
            "配置项: challenge_failed_action, challenge_timeout_action, challenge_timeout, "
            "challenge_type, enable_global_blacklist"
        )
        return
    try:
        await context.repository.set_group_config(chat_id, arguments[1], arguments[2], context.config.settings.defaults)
    except (ValueError, TypeError) as exc:
        await message.reply(str(exc))
        return
    await message.reply("配置项设置成功")


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


async def get_log(context: AppContext, _client: Client, message: Message) -> None:
    if message.from_user is None or not is_bot_admin(context, message.from_user.id):
        return
    if not message.command or len(message.command) != 2:
        await message.reply("使用方法: /getlog [challenge_id]")
        return
    logs = await context.repository.logs_by_challenge(message.command[1])
    await message.reply("\n".join(map(str, logs)) if logs else "没有找到相关记录")


async def get_user_by_ip(context: AppContext, client: Client, message: Message) -> None:
    if message.from_user is None or not is_bot_admin(context, message.from_user.id):
        return
    if not message.command or len(message.command) != 2:
        await message.reply("使用方法: /getuserbyip [ip]\n例如: `/getuserbyip 123.56.67.8`")
        return
    ip_addr = message.command[1]
    if not valid_ip(ip_addr):
        await message.reply("IP 地址格式错误")
        return
    logs = await context.repository.passed_users_by_ip(ip_addr)
    if not logs:
        await message.reply("没有找到通过该 IP 验证的用户")
        return
    groups: dict[int, list[tuple[int, object]]] = defaultdict(list)
    for group_id, user_id, last_passed_at in logs:
        groups[group_id].append((user_id, last_passed_at))
    titles: dict[int, str] = {}
    for group_id in groups:
        try:
            chat = await client.get_chat(group_id)
            titles[group_id] = chat.title or str(group_id)
        except RPCError:
            titles[group_id] = "无法获取群名"
    unique_users = len({user_id for _, user_id, _ in logs})
    text = (
        f"IP `{ip_addr}` 通过验证的用户共 {unique_users} 个，用户/群记录 {len(logs)} 条，涉及 {len(groups)} 个群:\n\n"
    )
    for group_id, users in groups.items():
        text += f"群组: {titles[group_id]} (`{group_id}`)\n"
        text += "".join(
            f"- [用户](tg://user?id={user_id}) `{user_id}` 最近通过: `{passed_at}`\n" for user_id, passed_at in users
        )
        text += "\n"
    for chunk in split_long_message(text):
        await message.reply(chunk, disable_web_page_preview=True)


async def ban_user_by_ip(context: AppContext, client: Client, message: Message) -> None:
    if message.from_user is None or not is_bot_admin(context, message.from_user.id):
        return
    if not message.command or len(message.command) != 3:
        await message.reply("使用方法: /banuserbyip [ip] [group_id]")
        return
    ip_addr = message.command[1]
    if not valid_ip(ip_addr):
        await message.reply("IP 地址格式错误")
        return
    try:
        group_id = int(message.command[2])
    except ValueError:
        await message.reply("群组 ID 格式错误")
        return
    user_ids = await context.repository.passed_user_ids_by_ip_and_group(ip_addr, group_id)
    if not user_ids:
        await message.reply("没有找到在该群通过这个 IP 验证的用户")
        return
    failures: list[tuple[int, str]] = []
    success = 0
    for user_id in user_ids:
        try:
            await client.ban_chat_member(group_id, user_id)
            success += 1
        except ChatAdminRequired:
            await message.reply("封禁失败: Bot 在该群没有封禁用户权限")
            return
        except RPCError as exc:
            failures.append((user_id, str(exc)))
    text = f"封禁完成: 成功 {success} 个，失败 {len(failures)} 个。"
    if failures:
        text += "\n\n失败列表:\n" + "".join(f"- `{user_id}`: `{error}`\n" for user_id, error in failures)
    for chunk in split_long_message(text):
        await message.reply(chunk)


async def forwarded_user_record(context: AppContext, _client: Client, message: Message) -> None:
    if message.from_user is None or not is_bot_admin(context, message.from_user.id):
        return
    if message.forward_from is None:
        await message.reply("该消息用户为频道或关闭了消息转发权限")
        return
    logs = await context.repository.logs_by_user(message.forward_from.id)
    await message.reply("\n".join(map(str, logs)) if logs else "没有找到相关记录")


def register_admin_handlers(client: Client, context: AppContext) -> None:
    handlers = [
        (reload_config, filters.command("reload") & filters.private),
        (help_command, filters.command("help") & filters.group),
        (ping_command, filters.command("ping") & filters.private),
        (call_admin, filters.command("admin", prefixes="@") & filters.group),
        (leave_command, filters.command("leave") & filters.private),
        (clean_database, filters.command("clean") & filters.private),
        (set_config, filters.command("faset") & filters.group),
        (sender_command, filters.command("sender") & filters.private),
        (get_log, filters.command("getlog") & filters.private),
        (get_user_by_ip, filters.command("getuserbyip") & filters.private),
        (ban_user_by_ip, filters.command("banuserbyip") & filters.private),
        (forwarded_user_record, filters.forwarded & filters.private),
    ]
    for callback, handler_filter in handlers:
        client.add_handler(MessageHandler(partial(callback, context), handler_filter))
