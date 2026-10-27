from __future__ import annotations

import hashlib
import hmac
import json
import time
from datetime import datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock
from urllib.parse import urlencode

import httpx
import pytest
from fastapi import FastAPI
from pyrogram.errors import ChannelPrivate, ChatAdminRequired, UserIdInvalid

from captcha_bot import miniapp_admin
from captcha_bot.config import Settings
from captcha_bot.db.repository import LogRecord


def init_data(user_id: int, token: str) -> str:
    fields = {"auth_date": str(int(time.time())), "user": json.dumps({"id": user_id, "first_name": "Admin"})}
    data_check_string = "\n".join(f"{key}={value}" for key, value in sorted(fields.items()))
    secret = hmac.new(b"WebAppData", token.encode(), hashlib.sha256).digest()
    return urlencode({**fields, "hash": hmac.new(secret, data_check_string.encode(), hashlib.sha256).hexdigest()})


LOG = LogRecord(-1001, 7, "challenge", "1.2.3.4", "UA", "Passed", datetime(2026, 1, 1, 12, 0))


def admin_app(settings: Settings) -> tuple[FastAPI, Any]:
    app = FastAPI()
    app.include_router(miniapp_admin.router)
    context = SimpleNamespace(
        config=SimpleNamespace(settings=settings, reload=AsyncMock()),
        client=SimpleNamespace(
            send_message=AsyncMock(),
            leave_chat=AsyncMock(),
            get_chat=AsyncMock(return_value=SimpleNamespace(title="G")),
            get_users=AsyncMock(return_value=[SimpleNamespace(is_deleted=True)]),
            ban_chat_member=AsyncMock(),
        ),
        repository=SimpleNamespace(
            all_blacklist_user_ids=AsyncMock(return_value=[7]),
            remove_blacklist_users=AsyncMock(),
            logs_by_challenge=AsyncMock(return_value=[LOG]),
            logs_by_user=AsyncMock(return_value=[]),
            passed_users_by_ip=AsyncMock(return_value=[(-1001, 7, LOG.created_at), (-1001, 8, None)]),
            passed_user_ids_by_ip_and_group=AsyncMock(return_value=[7, 8]),
        ),
    )
    app.state.context = context
    return app, context


def headers(settings: Settings, user_id: int | None = None) -> dict[str, str]:
    token = settings.bot.token.get_secret_value()
    return {"Authorization": f"tma {init_data(user_id or settings.bot.admin_ids[0], token)}"}


def http(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


@pytest.mark.asyncio
async def test_admin_api_requires_bot_admin(settings: Settings) -> None:
    app, context = admin_app(settings)
    async with http(app) as client:
        assert (await client.post("/miniapp/api/admin/reload")).status_code == 401
        denied = await client.post("/miniapp/api/admin/reload", headers=headers(settings, 999))
        assert denied.status_code == 403
        assert (await client.get("/miniapp/api/admin/ip/1.2.3.4", headers=headers(settings, 999))).status_code == 403
    context.config.reload.assert_not_awaited()


@pytest.mark.asyncio
async def test_admin_reload_and_leave(settings: Settings) -> None:
    app, context = admin_app(settings)
    async with http(app) as client:
        assert (await client.post("/miniapp/api/admin/reload", headers=headers(settings))).status_code == 200
        context.config.reload.side_effect = ValueError("bad")
        failed = await client.post("/miniapp/api/admin/reload", headers=headers(settings))
        assert failed.status_code == 400 and "bad" in failed.json()["detail"]

        left = await client.post("/miniapp/api/admin/leave", headers=headers(settings), json={"chat_id": -1001})
        assert left.status_code == 200
        context.client.leave_chat.assert_awaited_once_with(-1001, delete=True)
        positive = await client.post("/miniapp/api/admin/leave", headers=headers(settings), json={"chat_id": 5})
        assert positive.status_code == 422
        context.client.send_message.side_effect = ChannelPrivate()
        missing = await client.post("/miniapp/api/admin/leave", headers=headers(settings), json={"chat_id": -1002})
        assert missing.status_code == 400


@pytest.mark.asyncio
async def test_admin_logs_and_ip_lookup(settings: Settings) -> None:
    app, context = admin_app(settings)
    async with http(app) as client:
        logs = await client.get("/miniapp/api/admin/logs?challenge_id=challenge", headers=headers(settings))
        assert logs.json()["logs"][0]["ip_addr"] == "1.2.3.4"
        assert logs.json()["logs"][0]["created_at"] == "2026-01-01T12:00:00"
        by_user = await client.get("/miniapp/api/admin/logs?user_id=7", headers=headers(settings))
        assert by_user.json() == {"logs": []}
        context.repository.logs_by_user.assert_awaited_once_with(7)
        assert (await client.get("/miniapp/api/admin/logs", headers=headers(settings))).status_code == 400

        groups = (await client.get("/miniapp/api/admin/ip/1.2.3.4", headers=headers(settings))).json()["groups"]
        assert groups == [
            {
                "group_id": -1001,
                "title": "G",
                "users": [
                    {"user_id": 7, "last_passed_at": "2026-01-01T12:00:00"},
                    {"user_id": 8, "last_passed_at": None},
                ],
            }
        ]
        assert (await client.get("/miniapp/api/admin/ip/not-an-ip", headers=headers(settings))).status_code == 400


@pytest.mark.asyncio
async def test_admin_ban_by_ip(settings: Settings) -> None:
    app, context = admin_app(settings)
    url = "/miniapp/api/admin/ip/1.2.3.4/ban"
    async with http(app) as client:
        context.client.ban_chat_member.side_effect = [None, UserIdInvalid()]
        result = await client.post(url, headers=headers(settings), json={"group_id": -1001})
        assert result.json()["success"] == 1
        assert result.json()["failures"][0]["user_id"] == 8
        assert "#BAN_BY_IP" in context.client.send_message.await_args.args[1]

        context.client.ban_chat_member.side_effect = ChatAdminRequired()
        assert (await client.post(url, headers=headers(settings), json={"group_id": -1001})).status_code == 409

        context.repository.passed_user_ids_by_ip_and_group.return_value = []
        assert (await client.post(url, headers=headers(settings), json={"group_id": -1001})).status_code == 404


@pytest.mark.asyncio
async def test_admin_clean_runs_in_background(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    app, context = admin_app(settings)
    scheduled: list[Any] = []
    monkeypatch.setattr(miniapp_admin, "schedule", lambda coroutine, **_kwargs: scheduled.append(coroutine))
    async with http(app) as client:
        response = await client.post("/miniapp/api/admin/clean", headers=headers(settings))
    assert "1 个黑名单用户" in response.json()["message"]
    await scheduled[0]
    context.repository.remove_blacklist_users.assert_awaited_once_with([7])
    admin_id = settings.bot.admin_ids[0]
    assert context.client.send_message.await_args.args[0] == admin_id

    context.repository.all_blacklist_user_ids.side_effect = RuntimeError("boom")
    await miniapp_admin._clean_and_report(context, admin_id)
    assert "失败" in context.client.send_message.await_args.args[1]
