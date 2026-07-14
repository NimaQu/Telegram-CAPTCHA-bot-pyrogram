from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest

from captcha_bot.config import Settings
from captcha_bot.db.models import RecaptchaLogAction
from captcha_bot.db.repository import LogRecord, Repository, async_database_url


class Result:
    def __init__(self, values: list[Any]) -> None:
        self.values = values

    def __iter__(self):
        return iter(self.values)

    def all(self) -> list[Any]:
        return self.values


class Session:
    def __init__(self) -> None:
        self.get = AsyncMock(return_value=None)
        self.execute = AsyncMock(return_value=Result([]))
        self.scalar = AsyncMock(return_value=3)
        self.scalars = AsyncMock(return_value=Result([]))

    async def __aenter__(self) -> Session:
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None


class Sessions:
    def __init__(self) -> None:
        self.session = Session()

    def __call__(self) -> Session:
        return self.session

    def begin(self) -> Session:
        return self.session


def test_database_url_and_log_string() -> None:
    assert async_database_url("postgresql://u:p@host/db") == "postgresql+psycopg://u:p@host/db"
    assert async_database_url("postgresql+psycopg://u:p@host/db") == "postgresql+psycopg://u:p@host/db"
    with pytest.raises(ValueError, match="PostgreSQL"):
        async_database_url("sqlite:///db")
    assert "127.0.0.1" in str(LogRecord(-1, 2, "id", "127.0.0.1", "ua", "Passed", datetime.now()))


@pytest.mark.asyncio
async def test_repository_reads_and_atomic_writes(settings: Settings) -> None:
    sessions = Sessions()
    repository = Repository(cast(Any, sessions))
    assert await repository.get_blacklist_user(1) is None
    user = SimpleNamespace(user_id=1, last_attempt=datetime.now(), attempt_count=2)
    sessions.session.get.return_value = user
    record = await repository.get_blacklist_user(1)
    assert record is not None and record.attempt_count == 2

    await repository.record_blacklist_timeout(datetime.now(), 1)
    assert await repository.record_auto_kick(1, datetime.now()) == 3
    await repository.remove_blacklist_users([])
    await repository.remove_blacklist_users([1, 2])
    sessions.session.scalars.return_value = Result([1, 2])
    assert await repository.all_blacklist_user_ids() == [1, 2]
    assert sessions.session.execute.await_count == 2


@pytest.mark.asyncio
async def test_group_config_parsing_and_immediate_reads(settings: Settings) -> None:
    sessions = Sessions()
    repository = Repository(cast(Any, sessions))
    assert await repository.get_group_overrides(-1) is None
    sessions.session.get.return_value = SimpleNamespace(
        timeout=90,
        timeout_action="ban",
        failed_action="kick",
        challenge_type="recaptcha",
        global_blacklist=False,
    )
    overrides = await repository.get_group_overrides(-1)
    assert overrides is not None and overrides.challenge_timeout == 90 and not overrides.enable_global_blacklist

    await repository.set_group_config(-1, "CHALLENGE_TIMEOUT", "120", settings.defaults)
    await repository.set_group_config(-1, "challenge_type", "recaptcha", settings.defaults)
    await repository.set_group_config(-1, "challenge_failed_action", "ban", settings.defaults)
    await repository.set_group_config(-1, "enable_global_blacklist", "false", settings.defaults)
    with pytest.raises(ValueError, match="正整数"):
        await repository.set_group_config(-1, "challenge_timeout", "0", settings.defaults)
    with pytest.raises(ValueError, match="0/1"):
        await repository.set_group_config(-1, "enable_global_blacklist", "perhaps", settings.defaults)
    with pytest.raises(ValueError, match="不支持"):
        await repository.set_group_config(-1, "unknown", "1", settings.defaults)


@pytest.mark.asyncio
async def test_log_deduplication_queries_and_ip_lookups() -> None:
    sessions = Sessions()
    repository = Repository(cast(Any, sessions))
    await repository.log_recaptcha("id", 2, -1, "127.0.0.1", "ua", RecaptchaLogAction.PASSED)

    row = SimpleNamespace(
        group_id=-1,
        user_id=2,
        challenge_id="id",
        ip_addr="127.0.0.1",
        user_agent="ua",
        action="Passed",
        created_at=datetime.now(),
    )
    sessions.session.scalars.return_value = Result([row])
    assert len(await repository.logs_by_challenge("id")) == 1
    assert len(await repository.logs_by_user(2)) == 1
    assert len(await repository.logs_by_ip("127.0.0.1")) == 1

    sessions.session.execute.return_value = Result([SimpleNamespace(group_id=-1, user_id=2, last_passed_at=None)])
    assert await repository.passed_users_by_ip("127.0.0.1") == [(-1, 2, None)]
    sessions.session.scalars.return_value = Result([2, 3])
    assert await repository.passed_user_ids_by_ip_and_group("127.0.0.1", -1) == [2, 3]
