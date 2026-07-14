from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from captcha_bot.challenges import ChallengeKind, ChallengeRegistry, ChallengeSession
from captcha_bot.config import ConfigStore
from captcha_bot.services import TurnstileResult
from captcha_bot.web import client_ip, register_web_routes


class FakeDatabase:
    def __init__(self, healthy: bool = True) -> None:
        self.healthy = healthy

    async def healthcheck(self) -> bool:
        return self.healthy


class FakeRepository:
    def __init__(self) -> None:
        self.logs: list[tuple[Any, ...]] = []

    async def log_recaptcha(self, *args: Any) -> None:
        self.logs.append(args)


class FakeTurnstile:
    def __init__(self, success: bool) -> None:
        self.success = success

    async def verify(self, _token: str, _ip: str) -> TurnstileResult:
        return TurnstileResult(self.success)


class FakePolicies:
    def __init__(self, policy: Any) -> None:
        self.policy = policy

    async def get(self, _chat_id: int) -> Any:
        return self.policy


def web_app(settings, *, turnstile_success: bool = True) -> tuple[FastAPI, Any]:
    app = FastAPI()
    app.mount("/static", StaticFiles(directory="static"), name="static")
    register_web_routes(app, Jinja2Templates(directory="templates"))
    client = SimpleNamespace(
        is_connected=True,
        send_message=AsyncMock(),
        approve_chat_join_request=AsyncMock(),
        restrict_chat_member=AsyncMock(),
        delete_messages=AsyncMock(),
        edit_message_text=AsyncMock(),
    )
    context = SimpleNamespace(
        config=ConfigStore("config.example.toml", settings),
        database=FakeDatabase(),
        repository=FakeRepository(),
        registry=ChallengeRegistry(),
        turnstile=FakeTurnstile(turnstile_success),
        policies=FakePolicies(settings.defaults),
        client=client,
    )
    app.state.context = context
    return app, context


@pytest.mark.asyncio
async def test_status_health_and_missing_challenge(settings) -> None:
    app, context = web_app(settings)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        root = await client.get("/")
        assert root.status_code == 200
        assert root.headers["cache-control"] == "public, max-age=300"
        assert root.headers["x-frame-options"] == "DENY"
        health = await client.get("/healthz")
        assert health.json() == {"status": "ok"}
        missing = await client.get("/recaptcha")
        assert "没有这条验证数据" in missing.text
        context.database.healthy = False
        assert (await client.get("/healthz")).status_code == 503


@pytest.mark.asyncio
async def test_turnstile_get_failure_success_and_replay(settings) -> None:
    app, context = web_app(settings, turnstile_success=False)

    async def no_timeout(_session: ChallengeSession) -> None:
        return None

    session = ChallengeSession(
        "-1|42",
        ChallengeKind.TURNSTILE,
        -1,
        42,
        "group",
        turnstile_id="token",
        join_request=True,
    )
    await context.registry.register(session, 60, no_timeout)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        page = await client.get("/recaptcha?challenge=token", headers={"CF-Connecting-IP": "1.2.3.4"})
        assert page.status_code == 200
        assert page.headers["cache-control"] == "no-store"
        assert "replace-me" in page.text
        failed = await client.post("/recaptcha?challenge=token", data={"g-recaptcha-response": "bad"})
        assert "验证状态异常" in failed.text
        context.turnstile.success = True
        passed = await client.post("/recaptcha?challenge=token", data={"g-recaptcha-response": "ok"})
        assert "您已通过验证" in passed.text
        context.client.approve_chat_join_request.assert_awaited_once_with(-1, 42)
        replay = await client.post("/recaptcha?challenge=token", data={"g-recaptcha-response": "ok"})
        assert "没有这条验证数据" in replay.text
    assert len(context.repository.logs) == 3
    await context.registry.shutdown()


def test_client_ip_only_trusts_configured_proxy(settings) -> None:
    _, context = web_app(settings)
    trusted = cast(
        Request,
        SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"), headers={"CF-Connecting-IP": "8.8.8.8"}),
    )
    assert client_ip(trusted, context) == "8.8.8.8"
    untrusted = cast(
        Request,
        SimpleNamespace(client=SimpleNamespace(host="10.0.0.2"), headers={"CF-Connecting-IP": "8.8.8.8"}),
    )
    assert client_ip(untrusted, context) == "10.0.0.2"
    invalid = cast(Request, SimpleNamespace(client=SimpleNamespace(host="invalid"), headers={}))
    assert client_ip(invalid, context) == "127.0.0.1"
