from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest
from pyrogram.enums import ChatMemberStatus
from pyrogram.errors import ChatAdminRequired, MessageDeleteForbidden, UserNotParticipant

from captcha_bot.config import Settings
from captcha_bot.handlers import guestbot

CHAT_ID = -1001234
CALLER_ID = 501
BOT_ID = 900


def user(user_id: int, *, is_bot: bool = False, username: str | None = None) -> Any:
    return SimpleNamespace(id=user_id, first_name=f"u{user_id}", last_name=None, username=username, is_bot=is_bot)


def message(message_id: int, *, sender: Any = None, caller_user: Any = None, caller_chat: Any = None) -> Any:
    return SimpleNamespace(
        id=message_id,
        chat=SimpleNamespace(id=CHAT_ID, title="My group"),
        from_user=sender,
        guest_bot_caller_user=caller_user,
        guest_bot_caller_chat=caller_chat,
        text="点我头像项目一单给500",
        caption=None,
        delete=AsyncMock(),
    )


def make_context(settings: Settings, *, enabled: bool = True, caller_status: Any = ChatMemberStatus.MEMBER) -> Any:
    async def get_chat_member(_chat_id: int, _user_id: int) -> Any:
        if caller_status is None:
            raise UserNotParticipant()
        return SimpleNamespace(status=caller_status, privileges=None)

    client = SimpleNamespace(
        ban_chat_member=AsyncMock(),
        get_chat_member=AsyncMock(side_effect=get_chat_member),
        get_chat=AsyncMock(return_value=SimpleNamespace(linked_chat=SimpleNamespace(id=-100777))),
        send_message=AsyncMock(return_value=SimpleNamespace(id=55, delete=AsyncMock())),
    )
    policy = settings.defaults.model_copy(update={"block_guest_bots": enabled})
    return SimpleNamespace(
        client=client,
        config=SimpleNamespace(settings=settings),
        policies=SimpleNamespace(get=AsyncMock(return_value=policy)),
    )


@pytest.fixture(autouse=True)
def no_schedule(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(guestbot, "schedule", lambda coroutine, **_kwargs: coroutine.close())


def test_first_time_dedupes_per_caller() -> None:
    state = guestbot.GuestBotState()
    assert state.first_time(CHAT_ID, CALLER_ID, now=0)
    assert not state.first_time(CHAT_ID, CALLER_ID, now=10)
    assert state.first_time(CHAT_ID, 2, now=10)
    assert state.first_time(CHAT_ID, CALLER_ID, now=guestbot.HANDLED_SECONDS + 1)


def test_guest_reply_filter() -> None:
    plain = message(1, sender=user(CALLER_ID))
    guest = message(2, sender=user(BOT_ID, is_bot=True), caller_user=user(CALLER_ID))
    channel = message(3, sender=user(BOT_ID, is_bot=True), caller_chat=SimpleNamespace(id=-100555))
    assert not guestbot._is_guest_reply(None, cast(Any, None), plain)
    assert guestbot._is_guest_reply(None, cast(Any, None), guest)
    assert guestbot._is_guest_reply(None, cast(Any, None), channel)


@pytest.mark.asyncio
async def test_guest_reply_bans_caller_and_bot(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    logs: list[str] = []
    monkeypatch.setattr(guestbot, "send_log", AsyncMock(side_effect=lambda _ctx, text, **_kw: logs.append(text)))
    context = make_context(settings)
    client = context.client
    state = guestbot.GuestBotState()
    caller = user(CALLER_ID, username="pink")
    reply = message(13, sender=user(BOT_ID, is_bot=True, username="smwoobot"), caller_user=caller)

    await guestbot.block_guest_reply(context, state, client, reply)

    reply.delete.assert_awaited_once()
    client.ban_chat_member.assert_any_await(CHAT_ID, CALLER_ID)
    client.ban_chat_member.assert_any_await(CHAT_ID, BOT_ID)
    assert "#GUEST_BOT" in logs[0] and "@pink" in logs[0] and "@smwoobot" in logs[0]
    client.send_message.assert_awaited_once()

    # 同一次召唤的第二个 bot：只删回复、封 bot，不重复处置召唤者
    client.ban_chat_member.reset_mock()
    client.send_message.reset_mock()
    second = message(14, sender=user(901, is_bot=True), caller_user=caller)
    await guestbot.block_guest_reply(context, state, client, second)
    second.delete.assert_awaited_once()
    client.ban_chat_member.assert_awaited_once_with(CHAT_ID, 901)
    client.send_message.assert_not_awaited()
    assert len(logs) == 1


@pytest.mark.asyncio
async def test_guest_reply_ignored_when_disabled_or_admin_called(settings: Settings) -> None:
    for context in (
        make_context(settings, enabled=False),
        make_context(settings, caller_status=ChatMemberStatus.ADMINISTRATOR),
        make_context(settings, caller_status=ChatMemberStatus.OWNER),
    ):
        reply = message(13, sender=user(BOT_ID, is_bot=True), caller_user=user(CALLER_ID))
        await guestbot.block_guest_reply(context, guestbot.GuestBotState(), context.client, reply)
        reply.delete.assert_not_awaited()
        context.client.ban_chat_member.assert_not_awaited()


@pytest.mark.asyncio
async def test_guest_reply_from_anonymous_admin_or_linked_channel_is_ignored(settings: Settings) -> None:
    for caller_chat in (SimpleNamespace(id=CHAT_ID), SimpleNamespace(id=-100777)):
        context = make_context(settings)
        reply = message(13, sender=user(BOT_ID, is_bot=True), caller_chat=caller_chat)
        await guestbot.block_guest_reply(context, guestbot.GuestBotState(), context.client, reply)
        reply.delete.assert_not_awaited()
        context.client.ban_chat_member.assert_not_awaited()


@pytest.mark.asyncio
async def test_guest_reply_from_other_channel_bans_channel(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(guestbot, "send_log", AsyncMock())
    context = make_context(settings)
    channel = SimpleNamespace(id=-100555, title="Spam channel", username=None)
    reply = message(21, sender=user(BOT_ID, is_bot=True), caller_chat=channel)
    await guestbot.block_guest_reply(context, guestbot.GuestBotState(), context.client, reply)
    context.client.ban_chat_member.assert_any_await(CHAT_ID, -100555)
    reply.delete.assert_awaited_once()


@pytest.mark.asyncio
async def test_guest_reply_reports_missing_rights(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    logs: list[str] = []
    monkeypatch.setattr(guestbot, "send_log", AsyncMock(side_effect=lambda _ctx, text, **_kw: logs.append(text)))
    context = make_context(settings, caller_status=None)
    context.client.ban_chat_member.side_effect = ChatAdminRequired()
    reply = message(13, sender=user(BOT_ID, is_bot=True), caller_user=user(CALLER_ID))
    reply.delete.side_effect = MessageDeleteForbidden()
    await guestbot.block_guest_reply(context, guestbot.GuestBotState(), context.client, reply)
    assert "Bot 无权封禁" in logs[0] and "删除回复失败" in logs[0]
    context.client.send_message.assert_not_awaited()
