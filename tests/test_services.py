from __future__ import annotations

import httpx
import pytest

from captcha_bot.config import ConfigStore, FailedAction
from captcha_bot.db.repository import GroupOverrides
from captcha_bot.services import PolicyService, TurnstileService


class FakeRepository:
    def __init__(self, override: GroupOverrides | None) -> None:
        self.override = override

    async def get_group_overrides(self, group_id: int) -> GroupOverrides | None:
        del group_id
        return self.override


@pytest.mark.asyncio
async def test_policy_service_merges_database_override(settings) -> None:
    override = GroupOverrides(30, FailedAction.BAN, FailedAction.BAN, settings.defaults.challenge_type, False)
    service = PolicyService(ConfigStore("config.example.toml", settings), FakeRepository(override))
    policy = await service.get(-1)
    assert policy.challenge_timeout == 30
    assert policy.challenge_timeout_action == FailedAction.BAN
    assert not policy.enable_global_blacklist


@pytest.mark.asyncio
@pytest.mark.parametrize(("payload", "expected"), [({"success": True}, True), ({"success": False}, False)])
async def test_turnstile_result(settings, payload: dict[str, bool], expected: bool) -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        service = TurnstileService(client, ConfigStore("config.example.toml", settings))
        assert (await service.verify("response", "127.0.0.1")).success is expected


@pytest.mark.asyncio
async def test_turnstile_network_failure(settings) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await TurnstileService(client, ConfigStore("config.example.toml", settings)).verify(
            "response", "127.0.0.1"
        )
    assert not result.success
    assert result.error_codes == ("verification-unavailable",)
