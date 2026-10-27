from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest
from pyrogram.errors import ChannelPrivate

from captcha_bot.config import Settings
from captcha_bot.handlers import challenge, config
from captcha_bot.handlers.common import MemberRights


def context_for(settings: Settings) -> Any:
    return SimpleNamespace(config=SimpleNamespace(settings=settings), client=SimpleNamespace())


def message_for(*, user_id: int | None = 42, chat_id: int = -1001, command: list[str] | None = None) -> Any:
    reply = SimpleNamespace(id=501, delete=AsyncMock())
    return SimpleNamespace(
        id=50,
        from_user=SimpleNamespace(id=user_id) if user_id is not None else None,
        chat=SimpleNamespace(id=chat_id),
        command=command,
        chat_shared=None,
        reply=AsyncMock(return_value=reply),
        delete=AsyncMock(),
    )


@pytest.fixture(autouse=True)
def no_background_tasks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "schedule", lambda coroutine, **_kwargs: coroutine.close())


def button(message: Any) -> Any:
    return message.reply.await_args.kwargs["reply_markup"].inline_keyboard[0][0]


def test_parse_config_start() -> None:
    assert config.parse_config_start("config_-1001") == -1001
    assert config.parse_config_start("config_1001") is None
    assert config.parse_config_start("config_abc") is None
    assert config.parse_config_start("-1001") is None


@pytest.mark.asyncio
async def test_group_config_links_admins_to_private_chat(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    context = context_for(settings)
    rights = AsyncMock(return_value=MemberRights(True, True, True))
    monkeypatch.setattr(config, "fetch_member_rights", rights)
    message = message_for()
    await config.group_config_command(context, context.client, message)
    assert button(message).url == f"https://t.me/{settings.bot.username}?start=config_-1001"
    rights.assert_awaited_once_with(context.client, -1001, 42)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "result",
    [MemberRights(True, True, False), ChannelPrivate()],
)
async def test_group_config_denies_without_rights(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, result: Any
) -> None:
    context = context_for(settings)
    if isinstance(result, Exception):
        monkeypatch.setattr(config, "fetch_member_rights", AsyncMock(side_effect=result))
    else:
        monkeypatch.setattr(config, "fetch_member_rights", AsyncMock(return_value=result))
    message = message_for()
    await config.group_config_command(context, context.client, message)
    assert settings.messages.permission_denied in message.reply.await_args.args[0]


@pytest.mark.asyncio
async def test_group_config_rejects_anonymous_admin(settings: Settings) -> None:
    context = context_for(settings)
    message = message_for(user_id=None)
    await config.group_config_command(context, context.client, message)
    assert "匿名" in message.reply.await_args.args[0]


@pytest.mark.asyncio
async def test_private_config_offers_filtered_chat_picker(settings: Settings) -> None:
    context = context_for(settings)
    message = message_for(chat_id=42)
    await config.private_config_command(context, context.client, message)
    picker = message.reply.await_args.kwargs["reply_markup"].keyboard[0][0].request_chat
    assert picker.bot_is_member is True
    assert picker.chat_is_channel is False
    assert picker.user_administrator_rights.can_delete_messages is True
    assert picker.user_administrator_rights.can_restrict_members is True


@pytest.mark.asyncio
async def test_chat_shared_and_start_open_miniapp(settings: Settings) -> None:
    context = context_for(settings)
    shared = message_for(chat_id=42)
    shared.chat_shared = SimpleNamespace(
        button_id=config.CHAT_PICKER_BUTTON_ID, chat=SimpleNamespace(id=-1002, title="G")
    )
    await config.chat_shared(context, context.client, shared)
    assert button(shared).web_app.url == f"{settings.turnstile.base_url}/miniapp?chat_id=-1002"

    other = message_for(chat_id=42)
    other.chat_shared = SimpleNamespace(button_id=99, chat=SimpleNamespace(id=-1002, title="G"))
    await config.chat_shared(context, context.client, other)
    other.reply.assert_not_awaited()

    start = message_for(chat_id=42, command=["start", "config_-1003"])
    await challenge.start_command(context, context.client, start)
    assert button(start).web_app.url == f"{settings.turnstile.base_url}/miniapp?chat_id=-1003"


@pytest.mark.asyncio
async def test_admin_panel_only_for_bot_admins(settings: Settings) -> None:
    context = context_for(settings)
    outsider = message_for(user_id=999, chat_id=999)
    await config.admin_panel_command(context, context.client, outsider)
    outsider.reply.assert_not_awaited()

    admin = message_for(user_id=settings.bot.admin_ids[0], chat_id=settings.bot.admin_ids[0])
    await config.admin_panel_command(context, context.client, admin)
    assert button(admin).web_app.url == f"{settings.turnstile.base_url}/miniapp?view=admin"
