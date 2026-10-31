from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from collections.abc import AsyncIterator
from datetime import date, datetime, timedelta
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock
from urllib.parse import urlencode

import httpx
import pytest
from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from pydantic import SecretStr
from pyrogram.enums import ChatMemberStatus, ParseMode
from pyrogram.errors import ChatAdminRequired, MessageDeleteForbidden, UserIsBlocked
from pyrogram.types import InlineKeyboardButton, InlineKeyboardMarkup
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from captcha_bot.antispam import AntispamConfigModel, AntispamService, ReportVote
from captcha_bot.config import ConfigStore, Settings
from captcha_bot.db.models import Base
from captcha_bot.db.repository import Repository
from captcha_bot.handlers import antispam as handlers
from captcha_bot.handlers import report
from captcha_bot.jev import JevClient
from captcha_bot.miniapp import register_miniapp_routes
from captcha_bot.miniapp_antispam import router as antispam_router

CHAT_ID = -1001234
PNG = b"\x89PNG\r\n\x1a\n" + b"0" * 16
TOKEN = "123456:replace-me"


def init_data(user_id: int) -> str:
    fields = {
        "auth_date": str(int(time.time())),
        "user": json.dumps({"id": user_id, "first_name": "Admin", "username": "admin"}),
    }
    data_check_string = "\n".join(f"{key}={value}" for key, value in sorted(fields.items()))
    secret = hmac.new(b"WebAppData", TOKEN.encode(), hashlib.sha256).digest()
    digest = hmac.new(secret, data_check_string.encode(), hashlib.sha256).hexdigest()
    return urlencode({**fields, "hash": digest})


def member(status: ChatMemberStatus) -> Any:
    return SimpleNamespace(status=status, privileges=None, user=SimpleNamespace(id=42))


class FakeJev:
    def __init__(self) -> None:
        self.responses: list[httpx.Response] = []
        self.requests: list[dict[str, Any]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(json.loads(request.content))
        if self.responses:
            return self.responses.pop(0)
        return answers()


def answers(**values: float) -> httpx.Response:
    body = {
        "answers": {name: {"type": "noul", "noul": value} for name, value in values.items()},
        "usage": {"input_tokens": 50},
    }
    return httpx.Response(200, json=body)


@pytest.fixture
async def env(tmp_path: Path, settings: Settings, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[SimpleNamespace]:
    # 群通知的延迟删除不在测试里执行
    monkeypatch.setattr(handlers, "schedule", lambda coroutine, **_kwargs: coroutine.close())
    engine = create_async_engine(f"sqlite+aiosqlite:///{(tmp_path / 'antispam.sqlite').as_posix()}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    repository = Repository(async_sessionmaker(engine, expire_on_commit=False))
    fake = FakeJev()
    http = httpx.AsyncClient(transport=httpx.MockTransport(fake))
    configured = settings.model_copy(
        update={"antispam": settings.antispam.model_copy(update={"secret_key": SecretStr("s3cret")})}
    )
    config = ConfigStore("config.example.toml", configured)
    jev = JevClient(http, url="https://api.typesafe.ai/v1/systemone", model="jev-latest", timeout=5)
    service = AntispamService(config, repository, jev)
    notice = SimpleNamespace(id=900, delete=AsyncMock())
    client = SimpleNamespace(
        send_message=AsyncMock(return_value=notice),
        get_chat=AsyncMock(return_value=SimpleNamespace(bio="招代理", title="My group")),
        download_media=AsyncMock(return_value=BytesIO(PNG)),
        delete_messages=AsyncMock(),
        restrict_chat_member=AsyncMock(),
        ban_chat_member=AsyncMock(),
        unban_chat_member=AsyncMock(),
        get_media_group=AsyncMock(),
        get_chat_member=AsyncMock(return_value=member(ChatMemberStatus.OWNER)),
        edit_message_text=AsyncMock(),
        answer_callback_query=AsyncMock(),
    )
    context = SimpleNamespace(config=config, repository=repository, antispam=service, client=client)
    try:
        yield SimpleNamespace(context=context, client=client, fake=fake, repository=repository, service=service)
    finally:
        await http.aclose()
        await engine.dispose()


async def enable(env: SimpleNamespace, **config: Any) -> None:
    rules = AntispamConfigModel.model_validate({"builtin": {}, **config}).to_rules()
    await env.repository.set_antispam_key(
        CHAT_ID,
        encrypted=env.service.cipher().encrypt("sk-test-1234"),
        last4="1234",
        user_id=42,
        user_name="Admin",
        defaults=rules,
    )
    await env.repository.save_antispam_rules(CHAT_ID, rules)


def user(user_id: int = 7, **values: Any) -> Any:
    base = {
        "id": user_id,
        "first_name": "New",
        "last_name": "User",
        "username": "newbie",
        "is_bot": False,
        "photo": SimpleNamespace(big_file_id="avatar"),
    }
    return SimpleNamespace(**(base | values))


def message(text: str | None = "加我领福利", **values: Any) -> Any:
    base = {
        "id": 10,
        "chat": SimpleNamespace(id=CHAT_ID, title="My group"),
        "from_user": user(),
        "text": text,
        "caption": None,
        "entities": [SimpleNamespace(url="https://spam.example")],
        "caption_entities": None,
        "media_group_id": None,
        "forward_origin": SimpleNamespace(chat=SimpleNamespace(title="Ads", id=-100, username="ads")),
        "reply_markup": InlineKeyboardMarkup([[InlineKeyboardButton("点我", url="https://spam.example")]]),
        "photo": SimpleNamespace(file_id="photo", file_size=100),
        "document": None,
        "video": None,
        "animation": None,
        "video_note": None,
        "sticker": None,
    }
    return SimpleNamespace(**(base | values))


@pytest.mark.asyncio
async def test_first_message_spam_is_removed_logged_and_undoable(env: SimpleNamespace) -> None:
    await enable(env)
    await env.service.mark_new_member(CHAT_ID, 7)
    env.fake.responses.append(answers(ad=0.97, scam=0.2))

    await handlers.check_first_message(env.context, env.client, message())

    request = env.fake.requests[-1]
    assert set(request["assets"]) == {"sender_avatar", "message_image_1"}
    assert request["state"]["message"]["forwarded_from"] == "Ads (@ads)"
    assert "https://spam.example" in request["state"]["message"]["text"]
    assert request["state"]["sender"]["bio"] == "招代理"
    env.client.delete_messages.assert_awaited_once_with(CHAT_ID, [10])
    env.client.restrict_chat_member.assert_awaited_once()
    log_call, notice_call = env.client.send_message.await_args_list
    assert log_call.args[0] == env.context.config.settings.bot.log_channel_id
    assert "#ANTISPAM" in log_call.args[1] and "广告引流 97%" in log_call.args[1]
    assert log_call.kwargs["parse_mode"] == ParseMode.DISABLED
    assert notice_call.args[0] == CHAT_ID
    assert notice_call.kwargs["reply_markup"].inline_keyboard[0][0].callback_data == "as:undo:7"
    usage = await env.repository.antispam_usage(CHAT_ID, date.today())
    assert (usage.today_calls, usage.today_tokens) == (1, 50)

    # 只检查第一条
    await handlers.check_first_message(env.context, env.client, message())
    assert len(env.fake.requests) == 1

    query: Any = SimpleNamespace(
        id="q",
        data="as:undo:7",
        from_user=SimpleNamespace(id=42, first_name="Admin", last_name=None),
        message=SimpleNamespace(id=900, chat=SimpleNamespace(id=CHAT_ID)),
    )
    await handlers.undo_callback(env.context, env.client, query)
    env.client.unban_chat_member.assert_awaited_once_with(CHAT_ID, 7)
    assert "误判" in env.client.edit_message_text.await_args.args[2]
    env.client.answer_callback_query.assert_awaited_with("q", "已恢复")

    env.client.get_chat_member.return_value = member(ChatMemberStatus.MEMBER)
    await handlers.undo_callback(env.context, env.client, query)
    assert "管理员" in env.client.answer_callback_query.await_args.args[1]


@pytest.mark.asyncio
async def test_suspect_message_only_logged_and_clean_passes(env: SimpleNamespace) -> None:
    await enable(env, action="ban")
    for user_id in (7, 8):
        await env.service.mark_new_member(CHAT_ID, user_id)
    env.fake.responses += [answers(ad=0.6), answers(ad=0.1)]

    await handlers.check_first_message(env.context, env.client, message(from_user=user(7, photo=None)))
    env.client.delete_messages.assert_not_awaited()
    assert "#ANTISPAM_SUSPECT" in env.client.send_message.await_args.args[1]
    assert "assets" in env.fake.requests[0]

    env.client.send_message.reset_mock()
    await handlers.check_first_message(env.context, env.client, message(from_user=user(8), photo=None, text="hi"))
    env.client.send_message.assert_not_awaited()


@pytest.mark.asyncio
async def test_album_and_permission_errors(env: SimpleNamespace) -> None:
    await enable(env, action="kick")
    await env.service.mark_new_member(CHAT_ID, 7)
    album = [message(id=10, media_group_id=1), message(id=11, media_group_id=1, text=None, caption="第二张")]
    env.client.get_media_group.return_value = album
    env.client.delete_messages.side_effect = MessageDeleteForbidden()
    env.client.ban_chat_member.side_effect = ChatAdminRequired()
    env.fake.responses.append(answers(ad=0.99))

    await handlers.check_first_message(env.context, env.client, album[0])

    assert len(env.fake.requests[0]["state"]["message"]["images"]) == 2
    log_text = env.client.send_message.await_args_list[0].args[1]
    assert "Bot 无权删除消息" in log_text and "Bot 无权限制成员" in log_text


@pytest.mark.asyncio
async def test_key_error_disables_and_notifies_setter(env: SimpleNamespace) -> None:
    await enable(env)
    await env.service.mark_new_member(CHAT_ID, 7)
    env.fake.responses.append(httpx.Response(402, text="insufficient credit"))

    await handlers.check_first_message(env.context, env.client, message())

    record = await env.repository.get_antispam(CHAT_ID)
    assert record is not None and not record.enabled
    assert "HTTP 402" in (record.disabled_reason or "")
    dm = env.client.send_message.await_args
    assert dm.args[0] == 42
    assert "已自动关闭" in dm.args[1] and "insufficient credit" in dm.args[1]
    env.client.delete_messages.assert_not_awaited()

    # 已关闭的群不再记录新成员
    await env.service.mark_new_member(CHAT_ID, 9)
    assert not await env.repository.pop_antispam_pending(CHAT_ID, 9, timedelta(days=1))


@pytest.mark.asyncio
async def test_repeated_failures_disable_with_group_fallback(env: SimpleNamespace) -> None:
    await enable(env)
    env.client.send_message.side_effect = [UserIsBlocked(), SimpleNamespace(id=1)]
    for attempt in range(3):
        await env.service.mark_new_member(CHAT_ID, 100 + attempt)
        env.fake.responses.append(httpx.Response(503, text="down"))
        await handlers.check_first_message(env.context, env.client, message(from_user=user(100 + attempt)))
        record = await env.repository.get_antispam(CHAT_ID)
        assert record is not None
        assert record.enabled == (attempt < 2)
    fallback = env.client.send_message.await_args
    assert fallback.args[0] == CHAT_ID
    assert fallback.kwargs["parse_mode"] == ParseMode.HTML
    assert "tg://user?id=42" in fallback.args[1]


@pytest.mark.asyncio
async def test_rate_limit_and_bad_request_do_not_count(env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("captcha_bot.jev.asyncio.sleep", AsyncMock())
    await enable(env)
    for status in (429, 422):
        await env.service.mark_new_member(CHAT_ID, 7)
        env.fake.responses += [httpx.Response(status, text="x"), httpx.Response(status, text="x")]
        await handlers.check_first_message(env.context, env.client, message(photo=None, from_user=user(photo=None)))
    record = await env.repository.get_antispam(CHAT_ID)
    assert record is not None and record.enabled
    count, _ = await env.repository.record_antispam_failure(CHAT_ID, datetime.now())
    assert count == 1


@pytest.mark.asyncio
async def test_daily_limit_notifies_once(env: SimpleNamespace) -> None:
    await enable(env, daily_limit=1)
    await env.repository.add_antispam_usage(CHAT_ID, date.today(), 10)
    for user_id in (7, 8):
        await env.service.mark_new_member(CHAT_ID, user_id)
        await handlers.check_first_message(env.context, env.client, message(from_user=user(user_id)))
    assert env.fake.requests == []
    env.client.send_message.assert_awaited_once()
    assert "已达上限" in env.client.send_message.await_args.args[1]


@pytest.mark.asyncio
async def test_undecryptable_key_disables(env: SimpleNamespace) -> None:
    await enable(env)
    rules = AntispamConfigModel.defaults(10).to_rules()
    await env.repository.set_antispam_key(
        CHAT_ID, encrypted="garbage", last4="0000", user_id=42, user_name="A", defaults=rules
    )
    await env.repository.add_antispam_pending(CHAT_ID, 7, datetime.now())
    await handlers.check_first_message(env.context, env.client, message())
    record = await env.repository.get_antispam(CHAT_ID)
    assert record is not None and not record.enabled
    assert "无法解密" in (record.disabled_reason or "")


@pytest.mark.asyncio
async def test_ignored_messages(env: SimpleNamespace) -> None:
    await enable(env)
    await handlers.check_first_message(env.context, env.client, message(from_user=None))
    await handlers.check_first_message(env.context, env.client, message(from_user=user(is_bot=True)))
    await handlers.check_first_message(env.context, env.client, message())
    assert env.fake.requests == []


def test_message_image_sources_and_helpers() -> None:
    thumb = SimpleNamespace(file_id="thumb", file_size=10)
    video = message(photo=None, video=SimpleNamespace(thumbs=[thumb]))
    assert handlers._message_image_source(video) == ("thumb", 10)
    document = message(photo=None, document=SimpleNamespace(mime_type="image/png", file_id="doc", file_size=5))
    assert handlers._message_image_source(document) == ("doc", 5)
    assert handlers._message_image_source(message(photo=None)) == (None, None)
    assert handlers._forwarded_from(message(forward_origin=None)) is None
    origin = SimpleNamespace(chat=None, sender_chat=None, sender_user=user(5))
    assert handlers._forwarded_from(message(forward_origin=origin)) == "New User"
    hidden = SimpleNamespace(sender_user_name="Hidden")
    assert handlers._forwarded_from(message(forward_origin=hidden)) == "Hidden"
    assert handlers._buttons(message(reply_markup=None)) == ()


# ---- Mini App ----


def miniapp(env: SimpleNamespace) -> FastAPI:
    app = FastAPI()
    register_miniapp_routes(app, Jinja2Templates(directory="templates"))
    app.include_router(antispam_router)
    app.state.context = env.context
    return app


def auth(user_id: int = 42) -> dict[str, str]:
    return {"Authorization": f"tma {init_data(user_id)}"}


@pytest.mark.asyncio
async def test_miniapp_key_is_write_only(env: SimpleNamespace) -> None:
    base = f"/miniapp/api/chats/{CHAT_ID}/antispam"
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=miniapp(env)), base_url="http://test") as client:
        state = (await client.get(base, headers=auth())).json()
        assert state["available"] and not state["enabled"] and not state["key"]["set"]
        assert len(state["classifiers"]) == 7

        assert (await client.put(f"{base}/enabled", headers=auth(), json={"enabled": True})).status_code == 400

        env.fake.responses.append(httpx.Response(401, text="bad key"))
        rejected = await client.put(f"{base}/key", headers=auth(), json={"api_key": "sk-wrong-0000"})
        assert rejected.status_code == 400 and "token 无效" in rejected.json()["detail"]

        saved = await client.put(f"{base}/key", headers=auth(), json={"api_key": "sk-secret-9876"})
        body = saved.json()
        assert saved.status_code == 200 and body["enabled"]
        assert body["key"] == {
            "set": True,
            "last4": "9876",
            "set_by_name": "Admin",
            "set_at": body["key"]["set_at"],
            "mine": True,
        }
        assert "sk-secret" not in saved.text

        # 另一位管理员替换后原设置者收到通知
        replaced = await client.put(f"{base}/key", headers=auth(43), json={"api_key": "sk-other-5555"})
        assert replaced.json()["key"]["mine"] is True
        assert env.client.send_message.await_args.args[0] == 42
        assert "替换" in env.client.send_message.await_args.args[1]

        off = await client.put(f"{base}/enabled", headers=auth(), json={"enabled": False})
        assert not off.json()["enabled"]
        on = await client.put(f"{base}/enabled", headers=auth(), json={"enabled": True})
        assert on.json()["enabled"]

        config = AntispamConfigModel.defaults(500).model_dump(mode="json") | {"action": "ban", "rules": "允许链接"}
        updated = await client.put(base, headers=auth(), json=config)
        assert updated.json()["config"]["action"] == "ban"
        bad = config | {"act_threshold": 10, "log_threshold": 20}
        assert (await client.put(base, headers=auth(), json=bad)).status_code == 422

        cleared = await client.delete(f"{base}/key", headers=auth())
        assert not cleared.json()["key"]["set"] and not cleared.json()["enabled"]
        assert "清除" in env.client.send_message.await_args.args[1]


@pytest.mark.asyncio
async def test_miniapp_test_tab(env: SimpleNamespace) -> None:
    base = f"/miniapp/api/chats/{CHAT_ID}/antispam"
    config = AntispamConfigModel.defaults(500).model_dump(mode="json")
    payload = {"config": config, "text": "18元出已购Shadowrocket 独享密保号"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=miniapp(env)), base_url="http://test") as client:
        assert (await client.post(f"{base}/test", headers=auth(), json=payload)).status_code == 400
        await enable(env)
        assert (await client.post(f"{base}/test", headers=auth(), json=payload | {"text": " "})).status_code == 400

        trade = config | {"builtin": config["builtin"] | {"trade": {"enabled": True, "threshold": 90}}}
        env.fake.responses.append(answers(trade=0.95, ad=0.3))
        image = "data:image/png;base64," + base64.b64encode(PNG).decode()
        result = await client.post(
            f"{base}/test", headers=auth(), json=payload | {"config": trade, "images": [image], "avatar": image}
        )
        body = result.json()
        assert result.status_code == 200
        assert body["outcome"] == "act" and body["images_sent"]
        assert next(score for score in body["scores"] if score["key"] == "trade") == {
            "key": "trade",
            "name": "商品买卖",
            "percent": 95,
            "threshold": 90,
            "hit": True,
        }

        webp = base64.b64encode(b"RIFF0000WEBP").decode()
        assert (await client.post(f"{base}/test", headers=auth(), json=payload | {"images": [webp]})).status_code == 400
        assert (await client.post(f"{base}/test", headers=auth(), json=payload | {"images": ["!!"]})).status_code == 400

        env.fake.responses.append(httpx.Response(500, text="boom"))
        assert (await client.post(f"{base}/test", headers=auth(), json=payload)).status_code == 502


@pytest.mark.asyncio
async def test_miniapp_requires_rights_and_configuration(env: SimpleNamespace, settings: Settings) -> None:
    base = f"/miniapp/api/chats/{CHAT_ID}/antispam"
    app = miniapp(env)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        env.client.get_chat_member.return_value = member(ChatMemberStatus.MEMBER)
        assert (await client.get(base, headers=auth())).status_code == 403

        env.client.get_chat_member.return_value = member(ChatMemberStatus.OWNER)
        env.context.config = ConfigStore("config.example.toml", settings)
        env.service.config = env.context.config
        state = (await client.get(base, headers=auth())).json()
        assert not state["available"]
        unavailable = await client.put(f"{base}/key", headers=auth(), json={"api_key": "sk-secret-9876"})
        assert unavailable.status_code == 503


# ---- /report ----


def rights_by_user(admins: set[int]) -> Any:
    async def get_chat_member(_chat_id: int, user_id: int) -> Any:
        return member(ChatMemberStatus.OWNER if user_id in admins else ChatMemberStatus.MEMBER)

    return get_chat_member


def report_message(reporter: int, target: Any | None) -> Any:
    reply = SimpleNamespace(id=55, delete=AsyncMock())
    return SimpleNamespace(
        chat=SimpleNamespace(id=CHAT_ID, title="My group"),
        from_user=user(reporter, first_name=f"U{reporter}", last_name=None),
        reply_to_message=target,
        delete=AsyncMock(),
        reply=AsyncMock(return_value=reply),
    )


def vote_query(voter: int, message_id: int = 10) -> Any:
    return SimpleNamespace(
        id=f"q{voter}",
        data=f"as:vote:{message_id}",
        from_user=SimpleNamespace(id=voter, first_name="V", last_name=None),
        message=SimpleNamespace(id=900, chat=SimpleNamespace(id=CHAT_ID, title="My group")),
    )


@pytest.fixture
def report_env(env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    monkeypatch.setattr(report, "schedule", lambda coroutine, **_kwargs: coroutine.close())
    env.client.get_chat_member = AsyncMock(side_effect=rights_by_user({1}))
    env.client.edit_message_reply_markup = AsyncMock()
    env.client.get_messages = AsyncMock(return_value=message(empty=False))
    return env


@pytest.mark.asyncio
async def test_report_votes_then_jev_removes_spam(report_env: SimpleNamespace) -> None:
    env = report_env
    await enable(env, report_votes=3)
    command = report_message(20, message(empty=False))
    await report.report_command(env.context, env.client, command)

    command.delete.assert_awaited_once()
    poll = env.client.send_message.await_args
    assert poll.kwargs["reply_to_message_id"] == 10
    assert "(1/3)" in poll.kwargs["reply_markup"].inline_keyboard[0][0].text

    await report.vote_callback(env.context, env.client, vote_query(20))
    assert env.client.answer_callback_query.await_args.args[1] == "你已经投过票了"
    await report.vote_callback(env.context, env.client, vote_query(7))
    assert "自己" in env.client.answer_callback_query.await_args.args[1]
    await report.vote_callback(env.context, env.client, vote_query(21))
    markup = env.client.edit_message_reply_markup.await_args.kwargs["reply_markup"]
    assert "(2/3)" in markup.inline_keyboard[0][0].text
    assert env.fake.requests == []

    env.fake.responses.append(answers(ad=0.95))
    await report.vote_callback(env.context, env.client, vote_query(22))

    assert "被 3 位成员举报" in env.fake.requests[0]["state"]["context"]
    env.client.delete_messages.assert_any_await(CHAT_ID, [10])
    env.client.restrict_chat_member.assert_awaited_once()
    final = env.client.edit_message_text.await_args
    assert "AI 判定" in final.args[2] and "广告引流 95%" in final.args[2]
    assert final.kwargs["reply_markup"].inline_keyboard[0][0].callback_data == "as:undo:7"
    log = next(call for call in env.client.send_message.await_args_list if call.args[0] != CHAT_ID)
    assert "来源: 举报(3 人)" in log.args[1]
    assert env.service.reports == {}

    await report.vote_callback(env.context, env.client, vote_query(23))
    assert env.client.answer_callback_query.await_args.args[1] == "这次举报已经结束了"


@pytest.mark.asyncio
async def test_admin_report_is_judged_immediately(report_env: SimpleNamespace) -> None:
    env = report_env
    await enable(env, report_votes=5)
    env.fake.responses.append(answers(ad=0.1))
    await report.report_command(env.context, env.client, report_message(1, message(empty=False)))
    assert len(env.fake.requests) == 1
    assert "不是垃圾信息" in env.client.edit_message_text.await_args.args[2]
    env.client.delete_messages.assert_not_awaited()


@pytest.mark.asyncio
async def test_admin_vote_and_suspect_result(report_env: SimpleNamespace) -> None:
    env = report_env
    await enable(env, report_votes=5)
    await report.report_command(env.context, env.client, report_message(20, message(empty=False)))
    env.fake.responses.append(answers(ad=0.6))
    await report.vote_callback(env.context, env.client, vote_query(1))
    assert "不能确定" in env.client.edit_message_text.await_args.args[2]
    assert any("#ANTISPAM_SUSPECT" in str(call.args[1]) for call in env.client.send_message.await_args_list)


@pytest.mark.asyncio
async def test_report_second_reporter_adds_vote_and_failures(report_env: SimpleNamespace) -> None:
    env = report_env
    await enable(env, report_votes=2)
    await report.report_command(env.context, env.client, report_message(20, message(empty=False)))
    env.fake.responses.append(httpx.Response(500, text="boom"))
    await report.report_command(env.context, env.client, report_message(21, message(empty=False)))
    assert "暂时无法判断" in env.client.edit_message_text.await_args.args[2]

    env.client.get_messages.return_value = SimpleNamespace(empty=True, from_user=None)
    await report.report_command(env.context, env.client, report_message(20, message(empty=False)))
    await report.report_command(env.context, env.client, report_message(21, message(empty=False)))
    assert "不存在" in env.client.edit_message_text.await_args.args[2]


@pytest.mark.asyncio
async def test_report_rejections(report_env: SimpleNamespace) -> None:
    env = report_env

    async def hint_of(reporter: int, target: Any | None) -> str:
        command = report_message(reporter, target)
        await report.report_command(env.context, env.client, command)
        command.delete.assert_awaited_once()
        return command.reply.await_args.args[0]

    assert "没有开启" in await hint_of(20, message(empty=False))
    await enable(env, report_votes=0)
    assert "没有开启" in await hint_of(20, message(empty=False))
    await enable(env, report_votes=3)
    assert "请回复" in await hint_of(20, None)
    assert "不能被举报" in await hint_of(20, message(empty=False, from_user=user(1)))
    assert "不能被举报" in await hint_of(20, message(empty=False, from_user=user(30, is_bot=True)))
    assert "自己" in await hint_of(7, message(empty=False))
    env.client.send_message.assert_not_awaited()


@pytest.mark.asyncio
async def test_report_when_feature_unavailable_mid_vote(report_env: SimpleNamespace) -> None:
    env = report_env
    await enable(env, report_votes=2)
    await report.report_command(env.context, env.client, report_message(20, message(empty=False)))
    await env.repository.set_antispam_enabled(CHAT_ID, False)
    await report.vote_callback(env.context, env.client, vote_query(21))
    assert "暂时不可用" in env.client.edit_message_text.await_args.args[2]


@pytest.mark.asyncio
async def test_report_poll_expires(report_env: SimpleNamespace) -> None:
    env = report_env
    vote = ReportVote(CHAT_ID, 10, 7, 900, {20})
    env.service.reports[(CHAT_ID, 10)] = vote
    await report._expire(env.context, env.client, vote)
    env.client.delete_messages.assert_awaited_once_with(CHAT_ID, 900)
    assert env.service.reports == {}
    await report._expire(env.context, env.client, vote)
    env.client.delete_messages.assert_awaited_once()
