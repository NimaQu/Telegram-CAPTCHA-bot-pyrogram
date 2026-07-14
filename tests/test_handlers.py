from __future__ import annotations

from datetime import datetime, timedelta
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, Mock

import pytest
from pyrogram import Client
from pyrogram.enums import ChatMemberStatus, ChatType
from pyrogram.types import ChatJoinRequest

from captcha_bot.challenges import ChallengeKind, ChallengeRegistry, ChallengeSession
from captcha_bot.config import ChallengeType, Settings
from captcha_bot.db.repository import BlacklistRecord
from captcha_bot.handlers import admin, challenge


def context_for(settings: Settings, *, policy: Any | None = None) -> Any:
    client = SimpleNamespace(
        send_message=AsyncMock(return_value=SimpleNamespace(id=100)),
        leave_chat=AsyncMock(),
        get_messages=AsyncMock(),
        get_users=AsyncMock(),
        get_chat=AsyncMock(return_value=SimpleNamespace(title="group")),
        ban_chat_member=AsyncMock(),
        restrict_chat_member=AsyncMock(),
        approve_chat_join_request=AsyncMock(),
        decline_chat_join_request=AsyncMock(),
        edit_message_text=AsyncMock(),
        answer_callback_query=AsyncMock(),
        delete_messages=AsyncMock(),
        add_handler=lambda *_args, **_kwargs: None,
    )
    repository = SimpleNamespace(
        all_blacklist_user_ids=AsyncMock(return_value=[]),
        remove_blacklist_users=AsyncMock(),
        set_group_config=AsyncMock(),
        logs_by_challenge=AsyncMock(return_value=[]),
        logs_by_user=AsyncMock(return_value=[]),
        passed_users_by_ip=AsyncMock(return_value=[]),
        passed_user_ids_by_ip_and_group=AsyncMock(return_value=[]),
        get_blacklist_user=AsyncMock(return_value=None),
        record_auto_kick=AsyncMock(return_value=2),
        record_blacklist_timeout=AsyncMock(),
    )
    return SimpleNamespace(
        config=SimpleNamespace(settings=settings, reload=AsyncMock()),
        client=client,
        repository=repository,
        policies=SimpleNamespace(get=AsyncMock(return_value=policy or settings.defaults)),
        registry=ChallengeRegistry(),
    )


def message_for(
    *,
    user_id: int = 123456789,
    chat_id: int = -1001,
    text: str | None = None,
    command: list[str] | None = None,
) -> Any:
    reply = SimpleNamespace(id=501, delete=AsyncMock())
    return SimpleNamespace(
        id=50,
        from_user=SimpleNamespace(id=user_id, first_name="Admin"),
        chat=SimpleNamespace(id=chat_id, title="group"),
        text=text,
        command=command,
        forward_from=None,
        service=None,
        reply=AsyncMock(return_value=reply),
        delete=AsyncMock(),
    )


def query_for(*, user_id: int = 42, message_id: int = 100, data: str = "1") -> Any:
    return SimpleNamespace(
        id="query",
        data=data,
        from_user=SimpleNamespace(id=user_id, first_name="Mod"),
        message=SimpleNamespace(id=message_id, chat=SimpleNamespace(id=-1001)),
    )


def close_schedule(coroutine: Any, **_kwargs: Any) -> None:
    coroutine.close()


@pytest.mark.asyncio
async def test_basic_admin_commands_and_reload(settings: Settings) -> None:
    context = context_for(settings)
    message = message_for()
    await admin.help_command(context, context.client, message)
    await admin.ping_command(context, context.client, message)
    await admin.reload_config(context, context.client, message)
    assert message.reply.await_count == 3

    context.config.reload.side_effect = ValueError("bad")
    await admin.reload_config(context, context.client, message)
    assert "配置重载失败" in message.reply.await_args.args[0]

    outsider = message_for(user_id=999)
    await admin.reload_config(context, context.client, outsider)
    outsider.reply.assert_not_awaited()


@pytest.mark.asyncio
async def test_leave_and_set_config_commands(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    context = context_for(settings)
    usage = message_for(text="/leave")
    await admin.leave_command(context, context.client, usage)
    assert "使用方法" in usage.reply.await_args.args[0]

    valid = message_for(text="/leave -2002")
    await admin.leave_command(context, context.client, valid)
    context.client.leave_chat.assert_awaited_once_with(-2002, delete=True)

    monkeypatch.setattr(admin, "can_restrict_members", AsyncMock(return_value=True))
    command = message_for(text="/faset challenge_timeout 90")
    await admin.set_config(context, context.client, command)
    context.repository.set_group_config.assert_awaited_once()
    assert command.reply.await_args.args[0] == "配置项设置成功"

    context.repository.set_group_config.side_effect = ValueError("invalid")
    await admin.set_config(context, context.client, command)
    assert command.reply.await_args.args[0] == "invalid"

    monkeypatch.setattr(admin, "can_restrict_members", AsyncMock(return_value=False))
    monkeypatch.setattr(admin, "schedule", close_schedule)
    denied = message_for(text="/faset challenge_timeout 90")
    await admin.set_config(context, context.client, denied)
    assert denied.reply.await_args.args[0] == settings.messages.permission_denied


@pytest.mark.asyncio
async def test_admin_log_ip_sender_and_forward_commands(settings: Settings) -> None:
    context = context_for(settings)
    bad_sender = message_for(command=["sender", "bad"])
    await admin.sender_command(context, context.client, bad_sender)
    assert bad_sender.reply.await_args.args[0] == "链接格式错误"

    context.client.get_messages.return_value = [
        SimpleNamespace(from_user=SimpleNamespace(id=42, mention=lambda text: text))
    ]
    sender = message_for(command=["sender", "https://t.me/channel/10"])
    await admin.sender_command(context, context.client, sender)
    assert sender.reply.await_args.args[0] == "42"

    get_log = message_for(command=["getlog", "challenge"])
    context.repository.logs_by_challenge.return_value = ["record"]
    await admin.get_log(context, context.client, get_log)
    assert get_log.reply.await_args.args[0] == "record"

    invalid_ip = message_for(command=["getuserbyip", "bad"])
    await admin.get_user_by_ip(context, context.client, invalid_ip)
    assert invalid_ip.reply.await_args.args[0] == "IP 地址格式错误"

    context.repository.passed_users_by_ip.return_value = [(-1001, 42, datetime.now()), (-1001, 43, None)]
    by_ip = message_for(command=["getuserbyip", "127.0.0.1"])
    await admin.get_user_by_ip(context, context.client, by_ip)
    assert "用户共 2 个" in by_ip.reply.await_args.args[0]

    no_users = message_for(command=["banuserbyip", "127.0.0.1", "-1001"])
    await admin.ban_user_by_ip(context, context.client, no_users)
    assert "没有找到" in no_users.reply.await_args.args[0]
    context.repository.passed_user_ids_by_ip_and_group.return_value = [42, 43]
    await admin.ban_user_by_ip(context, context.client, no_users)
    assert "成功 2 个" in no_users.reply.await_args.args[0]

    forwarded = message_for()
    await admin.forwarded_user_record(context, context.client, forwarded)
    assert "关闭了消息转发权限" in forwarded.reply.await_args.args[0]
    forwarded.forward_from = SimpleNamespace(id=42)
    context.repository.logs_by_user.return_value = ["forwarded-record"]
    await admin.forwarded_user_record(context, context.client, forwarded)
    assert forwarded.reply.await_args.args[0] == "forwarded-record"


@pytest.mark.asyncio
async def test_clean_database_and_call_admin(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    context = context_for(settings)
    context.repository.all_blacklist_user_ids.return_value = [1, 2]
    context.client.get_users.side_effect = [
        [SimpleNamespace(is_deleted=True)],
        [SimpleNamespace(is_deleted=False)],
    ]
    message = message_for()
    await admin.clean_database(context, context.client, message)
    context.repository.remove_blacklist_users.assert_awaited_once_with([1])

    async def members(*_args: Any, **_kwargs: Any):
        yield SimpleNamespace(user=SimpleNamespace(id=1, is_bot=True), privileges=None)
        yield SimpleNamespace(
            user=SimpleNamespace(id=2, is_bot=False, mention=lambda text: f"@{text}"),
            status=ChatMemberStatus.OWNER,
            privileges=None,
        )

    context.client.get_me = AsyncMock(return_value=SimpleNamespace(id=10))
    context.client.get_chat_members = members
    monkeypatch.setattr(admin, "schedule", close_schedule)
    await admin.call_admin(context, context.client, message)
    assert message.reply.await_args.args[0] == "@admin"


@pytest.mark.asyncio
async def test_start_and_join_request_challenges(settings: Settings) -> None:
    context = context_for(settings)
    start = message_for(user_id=42, command=["start", "-1001"])
    await challenge.start_command(context, context.client, start)
    assert "不是你的验证数据" in start.reply.await_args.args[0]

    session = ChallengeSession(
        "-1001|42", ChallengeKind.TURNSTILE, -1001, 42, "group", turnstile_id="token", join_request=True
    )
    await context.registry.register(session, 60, AsyncMock())
    await challenge.start_command(context, context.client, start)
    assert "点击下方按钮" in start.reply.await_args.args[0]
    await context.registry.shutdown()

    request = SimpleNamespace(from_user=SimpleNamespace(id=42), chat=SimpleNamespace(id=-1001, title="group"))
    await challenge.on_chat_join_request(context, context.client, cast(ChatJoinRequest, request))
    created = await context.registry.find(42, -1001)
    assert created is not None and created.kind == ChallengeKind.MATH and created.message_id == 100
    await context.registry.shutdown()

    recaptcha_policy = settings.defaults.model_copy(update={"challenge_type": ChallengeType.RECAPTCHA})
    context = context_for(settings, policy=recaptcha_policy)
    await challenge.on_chat_join_request(context, context.client, cast(ChatJoinRequest, request))
    created = await context.registry.find(42, -1001)
    assert created is not None and created.kind == ChallengeKind.TURNSTILE and created.turnstile_id
    await context.registry.shutdown()


def member_update(*, user_id: int = 42, is_self: bool = False) -> Any:
    user = SimpleNamespace(
        id=user_id,
        is_self=is_self,
        username="user",
        first_name="First",
        last_name="Last",
    )
    return SimpleNamespace(
        via_join_request=False,
        new_chat_member=SimpleNamespace(user=user, status=ChatMemberStatus.MEMBER),
        old_chat_member=None,
        chat=SimpleNamespace(id=-1001, title="group", type=ChatType.SUPERGROUP),
        from_user=user,
    )


@pytest.mark.asyncio
async def test_member_join_math_turnstile_duplicate_and_self(settings: Settings) -> None:
    context = context_for(settings)
    await challenge.on_chat_member_updated(context, context.client, member_update(is_self=True))
    context.client.send_message.assert_awaited()

    update = member_update()
    await challenge.on_chat_member_updated(context, context.client, update)
    created = await context.registry.find(42, -1001)
    assert created is not None and created.kind == ChallengeKind.MATH and created.message_id == 100
    calls = context.client.restrict_chat_member.await_count
    await challenge.on_chat_member_updated(context, context.client, update)
    assert context.client.restrict_chat_member.await_count == calls
    await context.registry.shutdown()

    policy = settings.defaults.model_copy(update={"challenge_type": ChallengeType.RECAPTCHA})
    context = context_for(settings, policy=policy)
    await challenge.on_chat_member_updated(context, context.client, update)
    created = await context.registry.find(42, -1001)
    assert created is not None and created.kind == ChallengeKind.TURNSTILE
    await context.registry.shutdown()


@pytest.mark.asyncio
async def test_member_join_blacklist_windows(settings: Settings) -> None:
    update = member_update()
    context = context_for(settings)
    context.repository.get_blacklist_user.return_value = BlacklistRecord(
        42, datetime.now() - timedelta(seconds=1000), 1
    )
    await challenge.on_chat_member_updated(context, context.client, update)
    context.client.ban_chat_member.assert_awaited_once()
    context.repository.record_auto_kick.assert_awaited_once()
    await context.registry.shutdown()

    context = context_for(settings)
    context.repository.get_blacklist_user.return_value = BlacklistRecord(42, datetime.now(), 1)
    await challenge.on_chat_member_updated(context, context.client, update)
    context.repository.remove_blacklist_users.assert_awaited_once_with(42)
    assert await context.registry.find(42, -1001) is not None
    await context.registry.shutdown()


@pytest.mark.asyncio
async def test_private_math_callbacks(settings: Settings) -> None:
    for answer, approved in (("7", True), ("8", False)):
        context = context_for(settings)
        session = ChallengeSession("-1001|42", ChallengeKind.MATH, -1001, 42, "group", answer=7, join_request=True)
        await context.registry.register(session, 60, AsyncMock())
        query = query_for(data=f"{answer}|-1001")
        await challenge.callback_router(context, context.client, query)
        if approved:
            context.client.approve_chat_join_request.assert_awaited_once()
        else:
            context.client.decline_chat_join_request.assert_awaited_once()
        context.client.answer_callback_query.assert_awaited_once_with("query")
        await context.registry.shutdown()


@pytest.mark.asyncio
async def test_admin_callbacks_allow_deny_and_permissions(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(challenge, "schedule", close_schedule)
    for action in ("+", "-"):
        context = context_for(settings)
        session = ChallengeSession("-1001|100", ChallengeKind.MATH, -1001, 42, "group", message_id=100)
        await context.registry.register(session, 60, AsyncMock())
        monkeypatch.setattr(challenge, "can_restrict_members", AsyncMock(return_value=True))
        await challenge.callback_router(context, context.client, query_for(data=action))
        if action == "+":
            context.client.restrict_chat_member.assert_awaited_once()
        else:
            context.client.ban_chat_member.assert_awaited_once()
        await context.registry.shutdown()

    context = context_for(settings)
    session = ChallengeSession("-1001|100", ChallengeKind.MATH, -1001, 42, "group", message_id=100)
    await context.registry.register(session, 60, AsyncMock())
    monkeypatch.setattr(challenge, "can_restrict_members", AsyncMock(return_value=False))
    await challenge.admin_callback(context, context.client, query_for(data="+"), "+")
    assert await context.registry.get(session.key) is session
    assert context.client.answer_callback_query.await_args.args[1] == settings.messages.permission_denied
    await context.registry.shutdown()


@pytest.mark.asyncio
async def test_math_callbacks_correct_wrong_and_not_target(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(challenge, "schedule", close_schedule)
    for answer in ("7", "8"):
        context = context_for(settings)
        session = ChallengeSession("-1001|100", ChallengeKind.MATH, -1001, 42, "group", message_id=100, answer=7)
        await context.registry.register(session, 60, AsyncMock())
        await challenge.math_callback(context, context.client, query_for(), answer)
        if answer == "8":
            context.client.ban_chat_member.assert_awaited_once()
        context.client.answer_callback_query.assert_awaited_once()
        await context.registry.shutdown()

    context = context_for(settings)
    session = ChallengeSession("-1001|100", ChallengeKind.MATH, -1001, 42, "group", message_id=100, answer=7)
    await context.registry.register(session, 60, AsyncMock())
    await challenge.math_callback(context, context.client, query_for(user_id=99), "7")
    assert context.client.answer_callback_query.await_args.args[1] == settings.messages.challenge_not_for_you
    await context.registry.shutdown()


@pytest.mark.asyncio
async def test_delete_pending_and_timeouts(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(challenge.asyncio, "sleep", AsyncMock())
    monkeypatch.setattr(challenge, "schedule", close_schedule)
    context = context_for(settings)
    session = ChallengeSession("-1001|100", ChallengeKind.MATH, -1001, 42, "group", message_id=100)
    await context.registry.register(session, 60, AsyncMock())
    pending = message_for(user_id=42)
    await challenge.delete_pending_messages(context, context.client, pending)
    pending.delete.assert_awaited_once()
    await context.registry.shutdown()

    join = ChallengeSession("join", ChallengeKind.MATH, -1001, 42, "group", message_id=100, answer=7, join_request=True)
    await challenge.challenge_timeout(context, join)
    context.client.decline_chat_join_request.assert_awaited_once()

    normal = ChallengeSession("normal", ChallengeKind.MATH, -1001, 43, "group", message_id=101, answer=7)
    await challenge.challenge_timeout(context, normal)
    context.repository.record_blacklist_timeout.assert_awaited_once()
    context.client.ban_chat_member.assert_awaited()

    auto = ChallengeSession("auto", ChallengeKind.AUTO_KICK, -1001, 44, "group")
    calls = context.client.send_message.await_count
    await challenge.challenge_timeout(context, auto)
    assert context.client.send_message.await_count == calls


def test_registers_all_handlers(settings: Settings) -> None:
    context = context_for(settings)
    add_handler = Mock()
    client = cast(Client, SimpleNamespace(add_handler=add_handler))
    admin.register_admin_handlers(client, context)
    challenge.register_challenge_handlers(client, context)
    assert add_handler.call_count == 17
