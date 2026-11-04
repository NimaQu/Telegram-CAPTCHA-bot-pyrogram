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
from captcha_bot.asn import AsnInfo
from captcha_bot.config import Settings
from captcha_bot.db.repository import IpBlockRecord, LogRecord
from captcha_bot.ipblock import IpCheck, RuleError, RulePage


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
        geoip=SimpleNamespace(lookup=AsyncMock(return_value="中国 北京")),
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
        assert logs.json()["logs"][0]["ip_location"] == "中国 北京"
        by_user = await client.get("/miniapp/api/admin/logs?user_id=7", headers=headers(settings))
        assert by_user.json() == {"logs": []}
        context.repository.logs_by_user.assert_awaited_once_with(7)
        assert (await client.get("/miniapp/api/admin/logs", headers=headers(settings))).status_code == 400

        lookup = (await client.get("/miniapp/api/admin/ip/1.2.3.4", headers=headers(settings))).json()
        assert lookup["location"] == "中国 北京"
        groups = lookup["groups"]
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
        context.client.send_message.assert_not_awaited()

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


def blocklist_context(context: Any) -> None:
    rule = IpBlockRecord(1, "cidr", "108.187.4.0/24", "农场", 1, datetime(2026, 11, 4), 2, datetime(2026, 11, 4, 8))

    async def add(text: str, note: str, created_by: int | None) -> IpBlockRecord:
        if text == "bad":
            raise RuleError("无法识别")
        return rule

    async def remove(text: str) -> IpBlockRecord | None:
        return rule if text == "1" else None

    context.ipblock = SimpleNamespace(
        page=AsyncMock(return_value=RulePage([rule], 41, 3, 20)),
        add=AsyncMock(side_effect=add),
        remove=AsyncMock(side_effect=remove),
        check=AsyncMock(side_effect=lambda ip: IpCheck(ip, AsnInfo(138995, "Spam"), rule)),
        asn=SimpleNamespace(available=AsyncMock(return_value=False)),
    )


@pytest.mark.asyncio
async def test_admin_ip_block_rules(settings: Settings) -> None:
    app, context = admin_app(settings)
    blocklist_context(context)
    async with http(app) as client:
        assert (await client.get("/miniapp/api/admin/ipblock", headers=headers(settings, 999))).status_code == 403
        listed = (await client.get("/miniapp/api/admin/ipblock", headers=headers(settings))).json()
        assert listed["asn_available"] is False
        assert listed["rules"][0]["value"] == "108.187.4.0/24" and listed["rules"][0]["hits"] == 2
        assert (listed["total"], listed["page"], listed["pages"]) == (41, 3, 3)
        searched = await client.get("/miniapp/api/admin/ipblock?page=3&q=%20AS1%20", headers=headers(settings))
        assert searched.status_code == 200
        context.ipblock.page.assert_awaited_with(3, "AS1")
        assert (await client.get("/miniapp/api/admin/ipblock?page=0", headers=headers(settings))).status_code == 422

        added = await client.post(
            "/miniapp/api/admin/ipblock", headers=headers(settings), json={"rule": "108.187.4.79/24", "note": "农场"}
        )
        assert added.status_code == 200 and "#1" in added.json()["message"]
        context.ipblock.add.assert_awaited_with("108.187.4.79/24", "农场", settings.bot.admin_ids[0])
        bad = await client.post("/miniapp/api/admin/ipblock", headers=headers(settings), json={"rule": "bad"})
        assert bad.status_code == 400 and "无法识别" in bad.json()["detail"]

        assert (await client.delete("/miniapp/api/admin/ipblock/1", headers=headers(settings))).status_code == 200
        assert (await client.delete("/miniapp/api/admin/ipblock/9", headers=headers(settings))).status_code == 404

        checked = (await client.get("/miniapp/api/admin/ipblock/check/108.187.4.79", headers=headers(settings))).json()
        assert checked["asn"] == "AS138995 Spam" and checked["rule"]["id"] == 1
        invalid = await client.get("/miniapp/api/admin/ipblock/check/nope", headers=headers(settings))
        assert invalid.status_code == 400
