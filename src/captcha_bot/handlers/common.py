from __future__ import annotations

import asyncio
import logging
from collections.abc import Coroutine
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import ip_address
from typing import Any

from pyrogram import Client
from pyrogram.enums import ChatMemberStatus
from pyrogram.enums.chat_members_filter import ChatMembersFilter
from pyrogram.errors import (
    ChannelInvalid,
    ChannelPrivate,
    ChatAdminRequired,
    ChatIdInvalid,
    PeerIdInvalid,
    RPCError,
    UserIdInvalid,
    UserNotParticipant,
)
from pyrogram.types import ChatMember, ChatPermissions

from captcha_bot.config import FailedAction
from captcha_bot.context import AppContext

logger = logging.getLogger(__name__)


def is_bot_admin(context: AppContext, user_id: int) -> bool:
    return user_id in context.config.settings.bot.admin_ids


async def can_restrict_members(client: Client, chat_id: int, user_id: int) -> bool:
    async for member in client.get_chat_members(chat_id, filter=ChatMembersFilter.ADMINISTRATORS):
        if member.user.id != user_id:
            continue
        if member.status == ChatMemberStatus.OWNER:
            return True
        return bool(member.privileges and member.privileges.can_restrict_members)
    return False


class ChatUnavailable(Exception):
    pass


@dataclass(frozen=True, slots=True)
class MemberRights:
    is_admin: bool
    can_delete_messages: bool
    can_restrict_members: bool

    @property
    def can_configure(self) -> bool:
        return self.is_admin and self.can_delete_messages and self.can_restrict_members


NO_RIGHTS = MemberRights(False, False, False)


def member_rights(member: ChatMember) -> MemberRights:
    if member.status == ChatMemberStatus.OWNER:
        return MemberRights(True, True, True)
    if member.status != ChatMemberStatus.ADMINISTRATOR:
        return NO_RIGHTS
    privileges = member.privileges
    return MemberRights(
        True,
        bool(privileges and privileges.can_delete_messages),
        bool(privileges and privileges.can_restrict_members),
    )


async def fetch_member_rights(client: Client, chat_id: int, user_id: int | str) -> MemberRights:
    """每次实时查询 Telegram，不依赖本地缓存的管理员列表。"""
    try:
        return member_rights(await client.get_chat_member(chat_id, user_id))
    except UserNotParticipant:
        return NO_RIGHTS
    except PeerIdInvalid, UserIdInvalid:
        # Bot 尚未见过该用户时无法 resolve_peer，退回到实时拉取管理员列表
        pass
    except (ChannelPrivate, ChannelInvalid, ChatIdInvalid, ChatAdminRequired) as exc:
        raise ChatUnavailable from exc
    try:
        async for member in client.get_chat_members(chat_id, filter=ChatMembersFilter.ADMINISTRATORS):
            if member.user and member.user.id == user_id:
                return member_rights(member)
    except (ChannelPrivate, ChannelInvalid, ChatIdInvalid, ChatAdminRequired, PeerIdInvalid) as exc:
        raise ChatUnavailable from exc
    return NO_RIGHTS


def full_chat_permissions() -> ChatPermissions:
    return ChatPermissions(
        can_send_messages=True,
        can_send_other_messages=True,
        can_send_polls=True,
        can_add_web_page_previews=True,
        can_change_info=True,
        can_invite_users=True,
        can_pin_messages=True,
    )


async def send_log(context: AppContext, text: str) -> None:
    try:
        await context.client.send_message(context.config.settings.bot.log_channel_id, text)
    except RPCError:
        logger.exception("failed to send audit message")


async def apply_failed_action(client: Client, chat_id: int, user_id: int, action: FailedAction) -> None:
    if action == FailedAction.BAN:
        await client.ban_chat_member(chat_id, user_id)
    else:
        await client.ban_chat_member(chat_id, user_id, until_date=datetime.now() + timedelta(seconds=31))


def schedule(coroutine: Coroutine[Any, Any, Any], *, delay: float = 0, name: str) -> asyncio.Task[None]:
    async def runner() -> None:
        try:
            if delay:
                await asyncio.sleep(delay)
            await coroutine
        except asyncio.CancelledError:
            raise
        except RPCError:
            logger.exception("background Telegram operation failed", extra={"task": name})

    return asyncio.create_task(runner(), name=name)


def split_long_message(text: str, max_length: int = 3900) -> list[str]:
    chunks: list[str] = []
    current = ""
    for original_line in text.splitlines(keepends=True):
        line = original_line
        if len(current) + len(line) > max_length:
            if current:
                chunks.append(current)
                current = ""
            while len(line) > max_length:
                chunks.append(line[:max_length])
                line = line[max_length:]
        current += line
    if current:
        chunks.append(current)
    return chunks


def valid_ip(value: str) -> bool:
    try:
        ip_address(value)
        return True
    except ValueError:
        return False


def extract_message_ids(url: str) -> tuple[int | str, int]:
    from urllib.parse import urlparse

    path = urlparse(url).path
    parts = path.strip("/").split("/")
    if len(parts) < 2:
        raise ValueError("invalid Telegram message URL")
    if len(parts) >= 3 and parts[-3] == "c":
        return int(f"-100{int(parts[-2])}"), int(parts[-1])
    return parts[-2], int(parts[-1])
