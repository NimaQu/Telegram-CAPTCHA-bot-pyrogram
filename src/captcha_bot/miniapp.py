from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass
from typing import Annotated
from urllib.parse import parse_qsl

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field
from pyrogram.errors import RPCError

from captcha_bot.config import ChallengeType, DefaultPolicy, FailedAction
from captcha_bot.context import AppContext
from captcha_bot.db.repository import GroupOverrides
from captcha_bot.handlers.common import NO_RIGHTS, ChatUnavailable, fetch_member_rights, is_bot_admin, send_log

logger = logging.getLogger(__name__)

# Telegram 允许客户端时钟与服务器存在少量偏差
CLOCK_SKEW_SECONDS = 60


class InitDataError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class WebAppUser:
    id: int
    first_name: str
    username: str | None


@dataclass(frozen=True, slots=True)
class InitData:
    user: WebAppUser
    auth_date: int
    start_param: str | None


def validate_init_data(init_data: str, bot_token: str, *, max_age: int, now: float | None = None) -> InitData:
    """校验 Telegram.WebApp.initData，见 https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app"""
    try:
        pairs = parse_qsl(init_data, keep_blank_values=True, strict_parsing=True)
    except ValueError as exc:
        raise InitDataError("initData 格式错误") from exc
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise InitDataError("initData 含有重复字段")
    received_hash = fields.pop("hash", None)
    if not received_hash:
        raise InitDataError("initData 缺少签名")
    data_check_string = "\n".join(f"{key}={value}" for key, value in sorted(fields.items()))
    secret_key = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
    expected_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_hash, received_hash.lower()):
        raise InitDataError("initData 签名无效")
    try:
        auth_date = int(fields["auth_date"])
        raw_user = json.loads(fields["user"])
        user = WebAppUser(int(raw_user["id"]), str(raw_user.get("first_name", "")), raw_user.get("username"))
    except (KeyError, ValueError, TypeError) as exc:
        raise InitDataError("initData 缺少用户信息") from exc
    current = time.time() if now is None else now
    if auth_date > current + CLOCK_SKEW_SECONDS or current - auth_date > max_age:
        raise InitDataError("initData 已过期，请重新打开 Mini App")
    return InitData(user, auth_date, fields.get("start_param") or None)


class PolicyPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenge_timeout: int = Field(gt=0, le=3600, strict=True)
    challenge_timeout_action: FailedAction
    challenge_failed_action: FailedAction
    challenge_type: ChallengeType
    enable_global_blacklist: bool = Field(strict=True)

    @classmethod
    def from_policy(cls, policy: DefaultPolicy) -> PolicyPayload:
        return cls(
            challenge_timeout=policy.challenge_timeout,
            challenge_timeout_action=policy.challenge_timeout_action,
            challenge_failed_action=policy.challenge_failed_action,
            challenge_type=policy.challenge_type,
            enable_global_blacklist=policy.enable_global_blacklist,
        )

    def to_overrides(self) -> GroupOverrides:
        return GroupOverrides(
            challenge_timeout=self.challenge_timeout,
            challenge_timeout_action=self.challenge_timeout_action,
            challenge_failed_action=self.challenge_failed_action,
            challenge_type=self.challenge_type,
            enable_global_blacklist=self.enable_global_blacklist,
        )


@dataclass(frozen=True, slots=True)
class AuthorizedChat:
    user: WebAppUser
    chat_id: int
    title: str


def _context(request: Request) -> AppContext:
    return request.app.state.context


def authenticate(request: Request, authorization: str | None) -> InitData:
    settings = _context(request).config.settings
    scheme, _, init_data = (authorization or "").partition(" ")
    if scheme.lower() != "tma" or not init_data:
        raise HTTPException(401, "缺少 Telegram 身份信息，请从 Telegram 内打开")
    try:
        return validate_init_data(
            init_data, settings.bot.token.get_secret_value(), max_age=settings.web.miniapp_init_data_ttl
        )
    except InitDataError as exc:
        raise HTTPException(401, str(exc)) from exc


async def authorize(request: Request, chat_id: int, authorization: str | None) -> AuthorizedChat:
    context = _context(request)
    data = authenticate(request, authorization)
    if chat_id >= 0:
        raise HTTPException(400, "群组 ID 无效")
    try:
        rights = await fetch_member_rights(context.client, chat_id, data.user.id)
    except ChatUnavailable as exc:
        raise HTTPException(404, "Bot 不在该群组或没有管理员权限") from exc
    except RPCError as exc:
        logger.exception("failed to check member rights", extra={"chat_id": chat_id})
        raise HTTPException(502, "暂时无法从 Telegram 获取权限信息") from exc
    if not rights.can_configure:
        raise HTTPException(403, "需要该群的管理员权限，且至少拥有「删除消息」和「封禁/限制用户」")
    try:
        chat = await context.client.get_chat(chat_id)
        title = chat.title or str(chat_id)
    except RPCError:
        title = str(chat_id)
    return AuthorizedChat(data.user, chat_id, title)


async def chat_state(context: AppContext, chat: AuthorizedChat) -> dict[str, object]:
    policy = await context.policies.get(chat.chat_id)
    try:
        bot_rights = await fetch_member_rights(context.client, chat.chat_id, "me")
    except ChatUnavailable, RPCError:
        bot_rights = NO_RIGHTS
    return {
        "chat": {"id": chat.chat_id, "title": chat.title},
        "policy": PolicyPayload.from_policy(policy).model_dump(mode="json"),
        "bot": {
            "can_delete_messages": bot_rights.can_delete_messages,
            "can_restrict_members": bot_rights.can_restrict_members,
        },
    }


def register_miniapp_routes(app: FastAPI, templates: Jinja2Templates) -> None:
    @app.get("/miniapp", response_class=HTMLResponse)
    async def miniapp_page(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request=request, name="miniapp.html")

    @app.get("/miniapp/api/me")
    async def get_me(request: Request, authorization: Annotated[str | None, Header()] = None) -> dict[str, object]:
        data = authenticate(request, authorization)
        return {"user_id": data.user.id, "is_bot_admin": is_bot_admin(_context(request), data.user.id)}

    @app.get("/miniapp/api/chats/{chat_id}")
    async def get_chat_config(
        request: Request, chat_id: int, authorization: Annotated[str | None, Header()] = None
    ) -> dict[str, object]:
        chat = await authorize(request, chat_id, authorization)
        return await chat_state(_context(request), chat)

    @app.put("/miniapp/api/chats/{chat_id}")
    async def update_chat_config(
        request: Request,
        chat_id: int,
        payload: PolicyPayload,
        authorization: Annotated[str | None, Header()] = None,
    ) -> dict[str, object]:
        chat = await authorize(request, chat_id, authorization)
        context = _context(request)
        await context.repository.save_group_overrides(chat_id, payload.to_overrides())
        values = "\n".join(f"{key}: {value}" for key, value in payload.model_dump(mode="json").items())
        await send_log(
            context,
            f"#CONFIG_UPDATED\n管理员: {chat.user.id}\n群组 ID: {chat_id}\n群组标题: {chat.title}\n{values}",
        )
        return await chat_state(context, chat)
