from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest
from pyrogram.errors import PeerIdInvalid
from pyrogram.types import BotCommandScopeAllGroupChats, BotCommandScopeAllPrivateChats, BotCommandScopeChat

from captcha_bot.commands import ADMIN_COMMANDS, GROUP_COMMANDS, PRIVATE_COMMANDS, sync_bot_commands


@pytest.mark.asyncio
async def test_sync_bot_commands_scopes_admin_commands_to_admin_chats() -> None:
    client = cast(Any, SimpleNamespace(set_bot_commands=AsyncMock(side_effect=[True, True, PeerIdInvalid(), True])))
    await sync_bot_commands(client, [1, 2])
    calls = client.set_bot_commands.await_args_list
    assert [type(call.kwargs["scope"]) for call in calls] == [
        BotCommandScopeAllGroupChats,
        BotCommandScopeAllPrivateChats,
        BotCommandScopeChat,
        BotCommandScopeChat,
    ]
    assert calls[0].args[0] == GROUP_COMMANDS
    assert calls[1].args[0] == PRIVATE_COMMANDS
    assert calls[3].args[0] == PRIVATE_COMMANDS + ADMIN_COMMANDS
    assert calls[3].kwargs["scope"].chat_id == 2
    assert not {command.command for command in ADMIN_COMMANDS} & {
        command.command for command in GROUP_COMMANDS + PRIVATE_COMMANDS
    }


@pytest.mark.asyncio
async def test_sync_bot_commands_stops_when_public_commands_fail() -> None:
    client = cast(Any, SimpleNamespace(set_bot_commands=AsyncMock(side_effect=PeerIdInvalid())))
    await sync_bot_commands(client, [1])
    client.set_bot_commands.assert_awaited_once()
