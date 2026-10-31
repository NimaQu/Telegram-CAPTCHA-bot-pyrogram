"""Mini App 中各群的 AI 反垃圾配置：token 只写不读、开关、分类器、规则测试。"""

from __future__ import annotations

import base64
import binascii
import logging
from datetime import date, datetime
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from pyrogram.enums import ParseMode
from pyrogram.errors import RPCError

from captcha_bot.antispam import (
    ACTION_LABELS,
    BUILTIN_CLASSIFIERS,
    MAX_MESSAGE_IMAGES,
    AntispamConfigModel,
    AntispamService,
    SpamInput,
    key_last4,
)
from captcha_bot.context import AppContext
from captcha_bot.db.repository import AntispamKeyOwner, AntispamRecord
from captcha_bot.jev import ErrorKind, Image, JevError
from captcha_bot.miniapp import AuthorizedChat, authorize

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/miniapp/api/chats/{chat_id}/antispam")

AuthHeader = Annotated[str | None, Header()]
MAX_TEST_IMAGE_BYTES = 2 * 1024 * 1024


class KeyPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    api_key: str = Field(min_length=8, max_length=512)


class EnabledPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = Field(strict=True)


class TestPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    config: AntispamConfigModel
    text: str = Field(default="", max_length=4000)
    sender_name: str = Field(default="测试用户", max_length=128)
    username: str | None = Field(default=None, max_length=64)
    bio: str | None = Field(default=None, max_length=200)
    forwarded_from: str | None = Field(default=None, max_length=128)
    avatar: str | None = None
    images: list[str] = Field(default_factory=list, max_length=MAX_MESSAGE_IMAGES)


def _context(request: Request) -> AppContext:
    return request.app.state.context


def _service(request: Request) -> AntispamService:
    service = _context(request).antispam
    if not service.available:
        raise HTTPException(503, "Bot 管理员没有在配置文件中启用 AI 反垃圾(antispam.secret_key)")
    return service


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _jev_message(exc: JevError) -> str:
    if exc.kind == ErrorKind.KEY:
        return f"token 无效、无权限或余额不足：{exc.describe()}"
    return f"暂时无法验证 token：{exc.describe()}"


async def antispam_state(context: AppContext, chat: AuthorizedChat) -> dict[str, object]:
    service = context.antispam
    record = await context.repository.get_antispam(chat.chat_id)
    usage = await context.repository.antispam_usage(chat.chat_id, date.today())
    has_key = record is not None and bool(record.api_key_encrypted)
    return {
        "available": service.available,
        "send_images": service.settings.send_images,
        "enabled": bool(record and record.enabled and has_key),
        "key": {
            "set": has_key,
            "last4": record.key_last4 if record and has_key else None,
            "set_by_name": record.key_set_by_name if record and has_key else None,
            "set_at": _iso(record.key_set_at) if record and has_key else None,
            "mine": bool(record and has_key and record.key_set_by == chat.user.id),
        },
        "disabled_reason": record.disabled_reason if record else None,
        "disabled_at": _iso(record.disabled_at) if record else None,
        "config": service.group_config(record).model_dump(mode="json"),
        "classifiers": [
            {"id": item.id, "name": item.name, "yes": item.yes, "no": item.no} for item in BUILTIN_CLASSIFIERS
        ],
        "actions": [{"value": action.value, "label": label} for action, label in ACTION_LABELS.items()],
        "usage": {
            "today_calls": usage.today_calls,
            "today_tokens": usage.today_tokens,
            "month_calls": usage.month_calls,
            "month_tokens": usage.month_tokens,
        },
    }


async def _notify_replaced(
    context: AppContext, chat: AuthorizedChat, previous: AntispamKeyOwner, *, cleared: bool
) -> None:
    if previous.encrypted is None or previous.user_id is None or previous.user_id == chat.user.id:
        return
    verb = "清除" if cleared else "替换"
    try:
        await context.client.send_message(
            previous.user_id,
            f"你在群「{chat.title}」设置的 jev token 已被 {chat.user.first_name or chat.user.id} {verb}，"
            "之后不会再使用你的 token。",
            parse_mode=ParseMode.DISABLED,
        )
    except RPCError:
        logger.info("failed to notify previous antispam key owner", extra={"chat_id": chat.chat_id})


def _defaults(service: AntispamService, record: AntispamRecord | None) -> AntispamConfigModel:
    return service.group_config(record)


@router.get("")
async def get_antispam(request: Request, chat_id: int, authorization: AuthHeader = None) -> dict[str, object]:
    chat = await authorize(request, chat_id, authorization)
    return await antispam_state(_context(request), chat)


@router.put("")
async def save_antispam(
    request: Request, chat_id: int, payload: AntispamConfigModel, authorization: AuthHeader = None
) -> dict[str, object]:
    chat = await authorize(request, chat_id, authorization)
    _service(request)
    context = _context(request)
    await context.repository.save_antispam_rules(chat_id, payload.to_rules())
    logger.info("antispam config updated via Mini App", extra={"chat_id": chat_id, "admin_id": chat.user.id})
    return await antispam_state(context, chat)


@router.put("/key")
async def set_key(
    request: Request, chat_id: int, payload: KeyPayload, authorization: AuthHeader = None
) -> dict[str, object]:
    chat = await authorize(request, chat_id, authorization)
    service = _service(request)
    context = _context(request)
    api_key = payload.api_key.strip()
    try:
        await service.verify_key(api_key)
    except JevError as exc:
        raise HTTPException(400, _jev_message(exc)) from exc
    record = await context.repository.get_antispam(chat_id)
    previous = await context.repository.set_antispam_key(
        chat_id,
        encrypted=service.cipher().encrypt(api_key),
        last4=key_last4(api_key),
        user_id=chat.user.id,
        user_name=chat.user.first_name or chat.user.username,
        defaults=_defaults(service, record).to_rules(),
    )
    logger.info("antispam key set via Mini App", extra={"chat_id": chat_id, "admin_id": chat.user.id})
    await _notify_replaced(context, chat, previous, cleared=False)
    return await antispam_state(context, chat)


@router.delete("/key")
async def clear_key(request: Request, chat_id: int, authorization: AuthHeader = None) -> dict[str, object]:
    chat = await authorize(request, chat_id, authorization)
    service = _service(request)
    context = _context(request)
    record = await context.repository.get_antispam(chat_id)
    previous = await context.repository.set_antispam_key(
        chat_id,
        encrypted=None,
        last4=None,
        user_id=None,
        user_name=None,
        defaults=_defaults(service, record).to_rules(),
    )
    logger.info("antispam key cleared via Mini App", extra={"chat_id": chat_id, "admin_id": chat.user.id})
    await _notify_replaced(context, chat, previous, cleared=True)
    return await antispam_state(context, chat)


@router.put("/enabled")
async def set_enabled(
    request: Request, chat_id: int, payload: EnabledPayload, authorization: AuthHeader = None
) -> dict[str, object]:
    chat = await authorize(request, chat_id, authorization)
    service = _service(request)
    context = _context(request)
    record = await context.repository.get_antispam(chat_id)
    if payload.enabled:
        api_key = service.api_key(record) if record else None
        if api_key is None:
            raise HTTPException(400, "请先设置 jev token")
        try:
            await service.verify_key(api_key)
        except JevError as exc:
            raise HTTPException(400, _jev_message(exc)) from exc
    if record is not None:
        await context.repository.set_antispam_enabled(chat_id, payload.enabled)
    return await antispam_state(context, chat)


def _decode_image(value: str | None) -> Image | None:
    if not value:
        return None
    # 允许 data URL
    _, _, encoded = value.rpartition(",")
    try:
        data = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(400, "图片数据无效") from exc
    if len(data) > MAX_TEST_IMAGE_BYTES:
        raise HTTPException(400, "单张图片不能超过 2 MB")
    image = Image.detect(data)
    if image is None:
        raise HTTPException(400, "图片只支持 JPG 和 PNG")
    return image


@router.post("/test")
async def test_rules(
    request: Request, chat_id: int, payload: TestPayload, authorization: AuthHeader = None
) -> dict[str, object]:
    chat = await authorize(request, chat_id, authorization)
    service = _service(request)
    context = _context(request)
    record = await context.repository.get_antispam(chat_id)
    api_key = service.api_key(record) if record else None
    if api_key is None:
        raise HTTPException(400, "请先设置 jev token")
    if not payload.text.strip() and not payload.images and not payload.avatar:
        raise HTTPException(400, "请输入要测试的消息内容或上传图片")
    if not service.allow_test(chat_id, datetime.now()):
        raise HTTPException(429, f"测试太频繁，每小时最多 {service.settings.test_hourly_limit} 次")
    spam = SpamInput(
        text=payload.text,
        sender_name=payload.sender_name or "测试用户",
        username=(payload.username or "").removeprefix("@") or None,
        bio=payload.bio or None,
        forwarded_from=payload.forwarded_from or None,
        avatar=_decode_image(payload.avatar),
        images=tuple(image for value in payload.images if (image := _decode_image(value)) is not None),
    )
    try:
        verdict = await service.evaluate(api_key, payload.config, spam, chat.title)
    except JevError as exc:
        raise HTTPException(502, f"jev 请求失败：{exc.describe()}") from exc
    await context.repository.add_antispam_usage(chat_id, date.today(), verdict.input_tokens)
    return {
        "outcome": verdict.outcome,
        "images_sent": verdict.images_sent,
        "input_tokens": verdict.input_tokens,
        "scores": [
            {
                "key": score.classifier.key,
                "name": score.classifier.name,
                "percent": score.percent,
                "threshold": score.classifier.threshold,
                "hit": score in verdict.hits,
            }
            for score in verdict.scores
        ],
    }
