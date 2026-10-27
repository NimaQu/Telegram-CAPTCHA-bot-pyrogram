from __future__ import annotations

import hashlib
import hmac
import json
import time
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock
from urllib.parse import urlencode

import httpx
import pytest
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pyrogram.enums import ChatMemberStatus
from pyrogram.errors import ChannelPrivate, PeerIdInvalid, RPCError, UserNotParticipant

from captcha_bot.config import ConfigStore, Settings
from captcha_bot.db.repository import GroupOverrides
from captcha_bot.handlers.common import ChatUnavailable, fetch_member_rights, member_rights
from captcha_bot.miniapp import InitDataError, register_miniapp_routes, validate_init_data
from captcha_bot.miniapp_admin import router as admin_router
from captcha_bot.web import register_web_routes

TOKEN = "123456:replace-me"
CHAT_ID = -1001234


def sign(fields: dict[str, str], token: str = TOKEN) -> str:
    data_check_string = "\n".join(f"{key}={value}" for key, value in sorted(fields.items()))
    secret = hmac.new(b"WebAppData", token.encode(), hashlib.sha256).digest()
    digest = hmac.new(secret, data_check_string.encode(), hashlib.sha256).hexdigest()
    return urlencode({**fields, "hash": digest})


def init_data(user_id: int = 42, *, auth_date: int | None = None, **extra: str) -> str:
    fields = {
        "auth_date": str(int(time.time()) if auth_date is None else auth_date),
        "query_id": "AAH",
        "user": json.dumps({"id": user_id, "first_name": "Admin", "username": "admin"}),
        **extra,
    }
    return sign(fields)


def member(status: ChatMemberStatus, **privileges: bool) -> Any:
    return SimpleNamespace(
        status=status,
        privileges=SimpleNamespace(**privileges) if privileges else None,
        user=SimpleNamespace(id=42),
    )


def test_validate_init_data_accepts_signed_payload() -> None:
    data = validate_init_data(init_data(start_param="-1001"), TOKEN, max_age=60)
    assert data.user.id == 42
    assert data.user.username == "admin"
    assert data.start_param == "-1001"


@pytest.mark.parametrize(
    "payload",
    [
        "",
        "user=1",
        init_data().replace("hash=", "hash=0"),
        init_data(auth_date=int(time.time()) - 3600),
        init_data(auth_date=int(time.time()) + 3600),
        sign({"auth_date": str(int(time.time()))}),
        init_data() + "&user=x",
    ],
)
def test_validate_init_data_rejects_invalid_payload(payload: str) -> None:
    with pytest.raises(InitDataError):
        validate_init_data(payload, TOKEN, max_age=60)


def test_validate_init_data_rejects_other_bot_token() -> None:
    with pytest.raises(InitDataError):
        validate_init_data(init_data(), "654321:other", max_age=60)


def test_member_rights_requires_both_privileges() -> None:
    assert member_rights(member(ChatMemberStatus.OWNER)).can_configure
    assert member_rights(
        member(ChatMemberStatus.ADMINISTRATOR, can_delete_messages=True, can_restrict_members=True)
    ).can_configure
    assert not member_rights(
        member(ChatMemberStatus.ADMINISTRATOR, can_delete_messages=True, can_restrict_members=False)
    ).can_configure
    assert not member_rights(member(ChatMemberStatus.ADMINISTRATOR)).can_configure
    assert not member_rights(member(ChatMemberStatus.MEMBER)).can_configure


@pytest.mark.asyncio
async def test_fetch_member_rights_handles_telegram_errors() -> None:
    client: Any = SimpleNamespace(get_chat_member=AsyncMock(side_effect=UserNotParticipant()))
    assert not (await fetch_member_rights(client, CHAT_ID, 42)).is_admin

    client.get_chat_member.side_effect = ChannelPrivate()
    with pytest.raises(ChatUnavailable):
        await fetch_member_rights(client, CHAT_ID, 42)

    async def admins(*_args: Any, **_kwargs: Any) -> Any:
        yield member(ChatMemberStatus.OWNER)

    client = cast(Any, SimpleNamespace(get_chat_member=AsyncMock(side_effect=PeerIdInvalid()), get_chat_members=admins))
    assert (await fetch_member_rights(client, CHAT_ID, 42)).can_configure
    assert not (await fetch_member_rights(client, CHAT_ID, 7)).is_admin


class FakePolicies:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.overrides: GroupOverrides | None = None

    async def get(self, _chat_id: int) -> Any:
        if self.overrides is None:
            return self.settings.defaults
        return self.settings.defaults.model_copy(
            update={
                "challenge_timeout": self.overrides.challenge_timeout,
                "challenge_type": self.overrides.challenge_type,
            }
        )


def miniapp_app(settings: Settings, user_member: Any) -> tuple[FastAPI, Any]:
    app = FastAPI()
    app.mount("/static", StaticFiles(directory="static"), name="static")
    templates = Jinja2Templates(directory="templates")
    register_web_routes(app, templates)
    register_miniapp_routes(app, templates)
    app.include_router(admin_router)
    bot_member = member(ChatMemberStatus.ADMINISTRATOR, can_delete_messages=True, can_restrict_members=False)

    async def get_chat_member(_chat_id: int, user_id: int | str) -> Any:
        if isinstance(user_member, Exception):
            raise user_member
        return bot_member if user_id == "me" else user_member

    policies = FakePolicies(settings)

    async def save(_chat_id: int, overrides: GroupOverrides) -> None:
        policies.overrides = overrides

    context = SimpleNamespace(
        config=ConfigStore("config.example.toml", settings),
        client=SimpleNamespace(
            get_chat_member=AsyncMock(side_effect=get_chat_member),
            get_chat=AsyncMock(return_value=SimpleNamespace(title="My group")),
            send_message=AsyncMock(),
        ),
        repository=SimpleNamespace(save_group_overrides=AsyncMock(side_effect=save)),
        policies=policies,
    )
    app.state.context = context
    return app, context


def auth(user_id: int = 42) -> dict[str, str]:
    return {"Authorization": f"tma {init_data(user_id)}"}


PAYLOAD = {
    "challenge_timeout": 120,
    "challenge_timeout_action": "ban",
    "challenge_failed_action": "kick",
    "challenge_type": "recaptcha",
    "enable_global_blacklist": False,
}


@pytest.mark.asyncio
async def test_miniapp_page_can_be_framed_by_telegram_web(settings: Settings) -> None:
    app, _ = miniapp_app(settings, member(ChatMemberStatus.OWNER))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        page = await client.get("/miniapp")
    assert page.status_code == 200
    assert "telegram-web-app.js" in page.text
    assert "x-frame-options" not in page.headers
    assert "frame-ancestors https://web.telegram.org" in page.headers["content-security-policy"]


@pytest.mark.asyncio
async def test_miniapp_reads_and_updates_config(settings: Settings) -> None:
    app, context = miniapp_app(settings, member(ChatMemberStatus.OWNER))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        current = await client.get(f"/miniapp/api/chats/{CHAT_ID}", headers=auth())
        assert current.status_code == 200
        body = current.json()
        assert body["chat"] == {"id": CHAT_ID, "title": "My group"}
        assert body["policy"]["challenge_timeout"] == settings.defaults.challenge_timeout
        assert body["bot"] == {"can_delete_messages": True, "can_restrict_members": False}

        updated = await client.put(f"/miniapp/api/chats/{CHAT_ID}", headers=auth(), json=PAYLOAD)
        assert updated.status_code == 200
        assert updated.json()["policy"]["challenge_timeout"] == 120
        assert updated.json()["policy"]["challenge_type"] == "recaptcha"

        invalid = await client.put(
            f"/miniapp/api/chats/{CHAT_ID}", headers=auth(), json={**PAYLOAD, "challenge_timeout": 0}
        )
        assert invalid.status_code == 422
    context.repository.save_group_overrides.assert_awaited_once()
    assert "#CONFIG_UPDATED" in context.client.send_message.await_args.args[1]


@pytest.mark.asyncio
async def test_miniapp_rejects_unauthorized_requests(settings: Settings) -> None:
    weak_admin = member(ChatMemberStatus.ADMINISTRATOR, can_delete_messages=True, can_restrict_members=False)
    app, context = miniapp_app(settings, weak_admin)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.get(f"/miniapp/api/chats/{CHAT_ID}")).status_code == 401
        forged = {"Authorization": f"tma {init_data().replace('hash=', 'hash=0')}"}
        assert (await client.get(f"/miniapp/api/chats/{CHAT_ID}", headers=forged)).status_code == 401
        assert (await client.get("/miniapp/api/chats/42", headers=auth())).status_code == 400
        denied = await client.put(f"/miniapp/api/chats/{CHAT_ID}", headers=auth(), json=PAYLOAD)
        assert denied.status_code == 403
    context.repository.save_group_overrides.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(("error", "status"), [(ChannelPrivate(), 404), (RPCError(), 502)])
async def test_miniapp_reports_unavailable_chat(settings: Settings, error: Exception, status: int) -> None:
    app, _ = miniapp_app(settings, error)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(f"/miniapp/api/chats/{CHAT_ID}", headers=auth())
    assert response.status_code == status


@pytest.mark.asyncio
async def test_miniapp_me_reports_bot_admin(settings: Settings) -> None:
    app, _ = miniapp_app(settings, member(ChatMemberStatus.MEMBER))
    admin_id = settings.bot.admin_ids[0]
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.get("/miniapp/api/me", headers=auth(admin_id))).json() == {
            "user_id": admin_id,
            "is_bot_admin": True,
        }
        assert (await client.get("/miniapp/api/me", headers=auth())).json()["is_bot_admin"] is False
        assert (await client.get("/miniapp/api/me")).status_code == 401
