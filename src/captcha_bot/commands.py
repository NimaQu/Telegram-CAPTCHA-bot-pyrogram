"""启动时同步 Bot 命令菜单：普通用户只看到公开命令，Bot 管理员在私聊中额外看到管理命令。"""

from __future__ import annotations

import logging
from collections.abc import Iterable

from pyrogram import Client
from pyrogram.errors import RPCError
from pyrogram.types import (
    BotCommand,
    BotCommandScopeAllGroupChats,
    BotCommandScopeAllPrivateChats,
    BotCommandScopeChat,
)

logger = logging.getLogger(__name__)

GROUP_COMMANDS = [
    BotCommand("config", "群管理员打开群组配置面板"),
    BotCommand("help", "机器人介绍"),
]

PRIVATE_COMMANDS = [
    BotCommand("config", "选择要配置的群组"),
    BotCommand("sender", "根据消息链接查询发送者"),
]

ADMIN_COMMANDS = [
    BotCommand("admin", "打开 Bot 管理面板"),
    BotCommand("getlog", "按验证 ID 查询验证记录"),
    BotCommand("getuserbyip", "查询某 IP 通过验证的用户"),
    BotCommand("banuserbyip", "在指定群封禁某 IP 通过验证的用户"),
    BotCommand("leave", "让 Bot 离开指定群组"),
    BotCommand("reload", "重载配置文件"),
    BotCommand("clean", "清理黑名单中已删号的用户"),
    BotCommand("ping", "检查 Bot 是否在线"),
]


async def sync_bot_commands(client: Client, admin_ids: Iterable[int]) -> None:
    try:
        await client.set_bot_commands(GROUP_COMMANDS, scope=BotCommandScopeAllGroupChats())
        await client.set_bot_commands(PRIVATE_COMMANDS, scope=BotCommandScopeAllPrivateChats())
    except RPCError:
        logger.exception("failed to set public bot commands")
        return
    for admin_id in admin_ids:
        try:
            await client.set_bot_commands(PRIVATE_COMMANDS + ADMIN_COMMANDS, scope=BotCommandScopeChat(admin_id))
        except RPCError:
            # 管理员从未私聊过 Bot 时无法解析其 peer，私聊 Bot 后重启即可
            logger.warning("failed to set admin commands; has the admin started the bot?", extra={"admin_id": admin_id})
