"""Bot 管理员操作，Telegram 指令和 Mini App 共用。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from pyrogram.errors import BadRequest, ChatAdminRequired, RPCError
from pyrogram.types import User

from captcha_bot.context import AppContext


@dataclass(frozen=True, slots=True)
class CleanResult:
    deleted: list[int]
    failures: int


@dataclass(slots=True)
class IpGroup:
    group_id: int
    title: str
    users: list[tuple[int, datetime | None]] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class BanResult:
    success: int
    failures: list[tuple[int, str]]


async def leave_group(context: AppContext, chat_id: int) -> None:
    await context.client.send_message(chat_id, context.config.settings.messages.leave_message)
    await context.client.leave_chat(chat_id, delete=True)


async def clean_deleted_users(context: AppContext) -> CleanResult:
    user_ids = await context.repository.all_blacklist_user_ids()
    deleted: list[int] = []
    failures = 0
    for user_id in user_ids:
        try:
            user = await context.client.get_users(user_id)
        except BadRequest, IndexError:
            failures += 1
            deleted.append(user_id)
            continue
        if not isinstance(user, User):
            user = user[0]
        if user.is_deleted:
            deleted.append(user_id)
    await context.repository.remove_blacklist_users(deleted)
    return CleanResult(deleted, failures)


async def passed_users_by_ip(context: AppContext, ip_addr: str) -> list[IpGroup]:
    groups: dict[int, IpGroup] = {}
    for group_id, user_id, last_passed_at in await context.repository.passed_users_by_ip(ip_addr):
        if group_id not in groups:
            try:
                chat = await context.client.get_chat(group_id)
                title = chat.title or str(group_id)
            except RPCError:
                title = "无法获取群名"
            groups[group_id] = IpGroup(group_id, title)
        groups[group_id].users.append((user_id, last_passed_at))
    return list(groups.values())


async def ban_users_by_ip(context: AppContext, ip_addr: str, group_id: int) -> BanResult | None:
    """返回 None 表示该 IP 在该群没有通过记录；Bot 缺少权限时抛出 ChatAdminRequired。"""
    user_ids = await context.repository.passed_user_ids_by_ip_and_group(ip_addr, group_id)
    if not user_ids:
        return None
    failures: list[tuple[int, str]] = []
    success = 0
    for user_id in user_ids:
        try:
            await context.client.ban_chat_member(group_id, user_id)
            success += 1
        except ChatAdminRequired:
            raise
        except RPCError as exc:
            failures.append((user_id, str(exc)))
    return BanResult(success, failures)
