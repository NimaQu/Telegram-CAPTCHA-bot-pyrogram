from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from captcha_bot.antispam import (
    BUILTIN_CLASSIFIERS,
    AntispamAction,
    AntispamConfigModel,
    AntispamService,
    CustomClassifier,
    KeyCipher,
    SpamInput,
    active_classifiers,
    build_request,
    judge,
    key_last4,
    should_disable,
)
from captcha_bot.config import ConfigStore, Settings
from captcha_bot.db.models import Base
from captcha_bot.db.repository import AntispamRecord, Repository
from captcha_bot.jev import ErrorKind, Image, JevClient, JevError, JevResult, classify_error

PNG = b"\x89PNG\r\n\x1a\n" + b"0" * 16
JPEG = b"\xff\xd8\xff" + b"0" * 16
CHAT_ID = -1001234


def antispam_settings(settings: Settings, **values: Any) -> Settings:
    antispam = settings.antispam.model_copy(update={"secret_key": SecretStr("s3cret"), **values})
    return settings.model_copy(update={"antispam": antispam})


@pytest.fixture
async def repository(tmp_path: Path) -> AsyncIterator[Repository]:
    engine = create_async_engine(f"sqlite+aiosqlite:///{(tmp_path / 'antispam.sqlite').as_posix()}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    try:
        yield Repository(async_sessionmaker(engine, expire_on_commit=False))
    finally:
        await engine.dispose()


def jev_answers(**answers: float) -> dict[str, object]:
    return {
        "model": "jev-1.14.0",
        "answers": {name: {"type": "noul", "noul": value} for name, value in answers.items()},
        "usage": {"input_tokens": 120, "output_tokens": 3},
    }


def jev_client(handler: Callable[[httpx.Request], httpx.Response]) -> tuple[JevClient, httpx.AsyncClient]:
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return JevClient(http, url="https://api.typesafe.ai/v1/systemone", model="jev-latest", timeout=5), http


@pytest.mark.parametrize(
    ("status", "body", "kind"),
    [
        (401, "unauthorized", ErrorKind.KEY),
        (402, "", ErrorKind.KEY),
        (403, "model not allowed", ErrorKind.KEY),
        (500, '{"detail": "Insufficient balance"}', ErrorKind.KEY),
        (400, "bad", ErrorKind.BAD_REQUEST),
        (422, "[]", ErrorKind.BAD_REQUEST),
        (429, "slow down", ErrorKind.RATE_LIMITED),
        (529, "", ErrorKind.RATE_LIMITED),
        (502, "gateway", ErrorKind.FAILURE),
        (404, "missing", ErrorKind.FAILURE),
    ],
)
def test_classify_error(status: int, body: str, kind: ErrorKind) -> None:
    assert classify_error(status, body) == kind


def test_image_detect_only_accepts_png_and_jpeg() -> None:
    assert Image.detect(PNG) == Image(PNG, "png")
    assert Image.detect(JPEG) == Image(JPEG, "jpeg")
    assert Image.detect(b"RIFF....WEBP") is None


def test_config_defaults_and_validation() -> None:
    config = AntispamConfigModel.defaults(500)
    assert config.action == AntispamAction.MUTE
    assert {key for key, value in config.builtin.items() if not value.enabled} == {"trade", "service"}
    assert len(config.builtin) == len(BUILTIN_CLASSIFIERS)

    with pytest.raises(ValueError, match="未知的分类器"):
        AntispamConfigModel(builtin={"nope": {"enabled": True}})  # type: ignore[dict-item]
    with pytest.raises(ValueError, match="记录阈值"):
        AntispamConfigModel(builtin={}, act_threshold=50, log_threshold=60)
    with pytest.raises(ValueError):
        CustomClassifier(name="  ", yes="a", no="b")


def record_for(config: AntispamConfigModel, **values: Any) -> AntispamRecord:
    rules = config.to_rules()
    base: dict[str, Any] = {
        "chat_id": CHAT_ID,
        "enabled": True,
        "api_key_encrypted": None,
        "key_last4": None,
        "key_set_by": 42,
        "key_set_by_name": "Admin",
        "key_set_at": None,
        "disabled_reason": None,
        "disabled_at": None,
        "classifiers": rules.classifiers,
        "action": rules.action,
        "act_threshold": rules.act_threshold,
        "log_threshold": rules.log_threshold,
        "daily_limit": rules.daily_limit,
        "rules": rules.rules,
    }
    return AntispamRecord(**(base | values))


def test_config_round_trips_through_record() -> None:
    config = AntispamConfigModel(
        builtin={"trade": {"enabled": True, "threshold": 95}},  # type: ignore[dict-item]
        custom=[CustomClassifier(name="招聘", yes="招聘广告", no="正常聊天", threshold=70)],
        action=AntispamAction.BAN,
        rules=" 允许 GitHub 链接 ",
    )
    restored = AntispamConfigModel.from_record(record_for(config))
    assert restored.builtin["trade"].threshold == 95
    assert restored.custom[0].name == "招聘"
    assert restored.action == AntispamAction.BAN
    assert restored.rules == "允许 GitHub 链接"

    broken = AntispamConfigModel.from_record(record_for(config, classifiers="not json", daily_limit=7))
    assert broken == AntispamConfigModel.defaults(7)


def test_build_request_and_judge() -> None:
    config = AntispamConfigModel(
        builtin={"ad": {"enabled": True, "threshold": 60}, "porn": {"enabled": False}},  # type: ignore[dict-item]
        custom=[CustomClassifier(name="招聘", yes="招聘", no="不是")],
        act_threshold=85,
        log_threshold=40,
        rules="允许发 GitHub 链接",
    )
    active = {item.key: item for item in active_classifiers(config)}
    assert "porn" not in active
    assert active["ad"].threshold == 60
    assert active["custom_0"].threshold == 85

    spam = SpamInput(
        text="加我",
        sender_name="Spammer",
        username="spam",
        bio="招代理",
        forwarded_from="Ads",
        buttons=("点我 https://x.example",),
        avatar=Image(PNG, "png"),
        images=tuple(Image(JPEG, "jpeg") for _ in range(6)),
    )
    state, questions, assets = build_request(spam, config, "My group", with_images=True)
    assert set(assets) == {"sender_avatar"} | {f"message_image_{index}" for index in range(1, 5)}
    assert state["sender"] == {"name": "Spammer", "username": "@spam", "bio": "招代理", "avatar": "sender_avatar"}
    assert "允许发 GitHub 链接" in questions[0].instructions
    _, _, no_assets = build_request(spam, config, "My group", with_images=False)
    assert no_assets == {}

    hit = judge(config, JevResult({"ad": 0.7, "custom_0": 0.1}, 10), images_sent=True)
    assert hit.outcome == "act"
    assert hit.top is not None and hit.top.classifier.key == "ad"
    suspect = judge(config, JevResult({"ad": 0.5}, 10), images_sent=False)
    assert suspect.outcome == "log"
    clean = judge(config, JevResult({"ad": 0.1}, 10), images_sent=False)
    assert clean.outcome == "pass"
    quiet = config.model_copy(update={"log_threshold": 0})
    assert judge(quiet, JevResult({"ad": 0.5}, 1), images_sent=False).outcome == "pass"


def test_key_cipher_and_last4() -> None:
    cipher = KeyCipher("secret")
    token = cipher.encrypt("sk-live-123456")
    assert "123456" not in token
    assert cipher.decrypt(token) == "sk-live-123456"
    assert KeyCipher("other").decrypt(token) is None
    assert key_last4("sk-live-123456") == "3456"
    assert key_last4("short") == ""


def test_should_disable() -> None:
    now = datetime.now()
    assert should_disable(JevError(ErrorKind.KEY, "no"), 0, now, now)
    assert not should_disable(JevError(ErrorKind.RATE_LIMITED, "slow"), 9, now - timedelta(hours=1), now)
    assert not should_disable(JevError(ErrorKind.FAILURE, "down"), 2, now, now)
    assert should_disable(JevError(ErrorKind.FAILURE, "down"), 3, now, now)
    assert should_disable(JevError(ErrorKind.FAILURE, "down"), 1, now - timedelta(minutes=31), now)


@pytest.mark.asyncio
async def test_jev_client_success_and_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[httpx.Request] = []
    responses = [
        httpx.Response(200, json=jev_answers(ad=0.9)),
        httpx.Response(401, text="bad key"),
        httpx.Response(429, text="slow", headers={"Retry-After": "120"}),
        httpx.Response(200, json=jev_answers(ad=0.2)),
        httpx.Response(200, text="not json"),
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return responses.pop(0)

    sleeps: list[float] = []
    monkeypatch.setattr("captcha_bot.jev.asyncio.sleep", AsyncMock(side_effect=sleeps.append))
    client, http = jev_client(handler)
    async with http:
        result = await client.evaluate("key", {"a": 1}, [], {"photo": Image(PNG, "png")})
        assert result.answers == {"ad": 0.9}
        assert result.input_tokens == 120
        body = json.loads(seen[0].content)
        assert seen[0].headers["Authorization"] == "Bearer key"
        assert seen[0].headers["TypeSafe-Danger-Zone-Images"] == "true"
        assert body["assets"]["photo"]["format"] == "png"

        with pytest.raises(JevError) as error:
            await client.evaluate("key", "x", [])
        assert error.value.kind == ErrorKind.KEY
        assert error.value.describe() == "HTTP 401: bad key"
        assert "TypeSafe-Danger-Zone-Images" not in seen[1].headers

        assert (await client.evaluate("key", "x", [])).answers == {"ad": 0.2}
        assert sleeps == [10.0]

        with pytest.raises(JevError) as error:
            await client.evaluate("key", "x", [])
        assert error.value.kind == ErrorKind.FAILURE


@pytest.mark.asyncio
async def test_jev_client_network_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    client, http = jev_client(handler)
    async with http:
        with pytest.raises(JevError) as error:
            await client.evaluate("key", "x", [])
    assert error.value.kind == ErrorKind.FAILURE
    assert error.value.status is None
    assert "ConnectError" in error.value.describe()


@pytest.mark.asyncio
async def test_service_falls_back_to_text_when_images_rejected(settings: Settings, repository: Repository) -> None:
    requests: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        requests.append(payload)
        if "assets" in payload:
            return httpx.Response(400, text="images not supported")
        return httpx.Response(200, json=jev_answers(ad=0.99))

    client, http = jev_client(handler)
    service = AntispamService(ConfigStore("config.example.toml", antispam_settings(settings)), repository, client)
    config = AntispamConfigModel.defaults(10)
    async with http:
        verdict = await service.evaluate("key", config, SpamInput("hi", "u", images=(Image(PNG, "png"),)), "g")
        assert verdict.outcome == "act"
        assert not verdict.images_sent
        assert len(requests) == 2

        empty = AntispamConfigModel.model_validate({"builtin": {key: {"enabled": False} for key in config.builtin}})
        assert (await service.evaluate("key", empty, SpamInput("hi", "u"), "g")).outcome == "pass"
        assert len(requests) == 2


@pytest.mark.asyncio
async def test_service_test_limit_and_pending(settings: Settings, repository: Repository) -> None:
    client, http = jev_client(lambda _request: httpx.Response(200, json=jev_answers()))
    configured = antispam_settings(settings, test_hourly_limit=2)
    service = AntispamService(ConfigStore("config.example.toml", configured), repository, client)
    now = datetime.now()
    assert service.allow_test(CHAT_ID, now)
    assert service.allow_test(CHAT_ID, now)
    assert not service.allow_test(CHAT_ID, now)
    assert service.allow_test(CHAT_ID, now + timedelta(hours=2))

    await service.mark_new_member(CHAT_ID, 7)
    assert not await repository.pop_antispam_pending(CHAT_ID, 7, timedelta(days=1))

    rules = service.group_config(None).to_rules()
    encrypted = service.cipher().encrypt("sk-test-0000")
    await repository.set_antispam_key(
        CHAT_ID, encrypted=encrypted, last4="0000", user_id=42, user_name="Admin", defaults=rules
    )
    await service.mark_new_member(CHAT_ID, 7)
    assert await repository.pop_antispam_pending(CHAT_ID, 7, timedelta(days=1))
    assert not await repository.pop_antispam_pending(CHAT_ID, 7, timedelta(days=1))
    record = await repository.get_antispam(CHAT_ID)
    assert record is not None
    assert service.api_key(record) == "sk-test-0000"
    async with http:
        await service.verify_key("sk-test-0000")

    unconfigured = AntispamService(ConfigStore("config.example.toml", settings), repository, client)
    assert not unconfigured.available
    assert unconfigured.api_key(record) is None
    with pytest.raises(RuntimeError):
        unconfigured.cipher()
    await unconfigured.mark_new_member(CHAT_ID, 8)
    assert not await repository.pop_antispam_pending(CHAT_ID, 8, timedelta(days=1))


@pytest.mark.asyncio
async def test_repository_antispam_lifecycle(repository: Repository) -> None:
    rules = AntispamConfigModel.defaults(3).to_rules()
    assert await repository.get_antispam(CHAT_ID) is None
    await repository.save_antispam_rules(CHAT_ID, rules)
    record = await repository.get_antispam(CHAT_ID)
    assert record is not None and not record.enabled and record.daily_limit == 3

    previous = await repository.set_antispam_key(
        CHAT_ID, encrypted="enc-1", last4="1111", user_id=1, user_name="A", defaults=rules
    )
    assert previous.user_id is None
    previous = await repository.set_antispam_key(
        CHAT_ID, encrypted="enc-2", last4="2222", user_id=2, user_name="B", defaults=rules
    )
    assert (previous.user_id, previous.encrypted) == (1, "enc-1")

    now = datetime.now()
    assert await repository.record_antispam_failure(CHAT_ID, now) == (1, now)
    count, first = await repository.record_antispam_failure(CHAT_ID, now + timedelta(minutes=1))
    assert (count, first) == (2, now)
    await repository.reset_antispam_failures(CHAT_ID)
    assert (await repository.record_antispam_failure(CHAT_ID, now))[0] == 1
    assert await repository.record_antispam_failure(-1, now) == (0, now)

    assert await repository.disable_antispam(CHAT_ID, "bad key", now)
    assert not await repository.disable_antispam(CHAT_ID, "bad key", now)
    record = await repository.get_antispam(CHAT_ID)
    assert record is not None and not record.enabled and record.disabled_reason == "bad key"
    await repository.set_antispam_enabled(CHAT_ID, True)
    record = await repository.get_antispam(CHAT_ID)
    assert record is not None and record.enabled and record.disabled_reason is None

    previous = await repository.set_antispam_key(
        CHAT_ID, encrypted=None, last4=None, user_id=None, user_name=None, defaults=rules
    )
    assert previous.user_id == 2
    record = await repository.get_antispam(CHAT_ID)
    assert record is not None and not record.enabled and record.api_key_encrypted is None

    today = date.today()
    await repository.add_antispam_pending(CHAT_ID, 5, datetime.now() - timedelta(days=40))
    assert not await repository.pop_antispam_pending(CHAT_ID, 5, timedelta(days=30))
    assert await repository.antispam_calls(CHAT_ID, today) == 0
    await repository.add_antispam_usage(CHAT_ID, today, 100)
    await repository.add_antispam_usage(CHAT_ID, today, 50)
    await repository.add_antispam_usage(CHAT_ID, today.replace(day=1) - timedelta(days=1), 999)
    assert await repository.antispam_calls(CHAT_ID, today) == 2
    usage = await repository.antispam_usage(CHAT_ID, today)
    assert (usage.today_calls, usage.today_tokens) == (2, 150)
    assert usage.month_calls >= 2
    assert await repository.mark_antispam_limit_notified(CHAT_ID, today)
    assert not await repository.mark_antispam_limit_notified(CHAT_ID, today)
