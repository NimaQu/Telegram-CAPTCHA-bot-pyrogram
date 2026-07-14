from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from captcha_bot.config import ChallengeType, DefaultPolicy, FailedAction, Settings
from captcha_bot.db.models import BlacklistUser, GroupConfig, RecaptchaLog, RecaptchaLogAction


@dataclass(frozen=True, slots=True)
class BlacklistRecord:
    user_id: int
    last_attempt: datetime
    attempt_count: int


@dataclass(frozen=True, slots=True)
class GroupOverrides:
    challenge_timeout: int
    challenge_timeout_action: FailedAction
    challenge_failed_action: FailedAction
    challenge_type: ChallengeType
    enable_global_blacklist: bool


@dataclass(frozen=True, slots=True)
class LogRecord:
    group_id: int
    user_id: int
    challenge_id: str
    ip_addr: str
    user_agent: str
    action: str
    created_at: datetime | None

    def __str__(self) -> str:
        return f"IP地址: `{self.ip_addr}`\nUA：`{self.user_agent}`\n状态：`{self.action}`\n时间：`{self.created_at}`\n"


def async_database_url(url: str) -> str:
    if url.startswith("postgresql+psycopg://"):
        return url
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg://", 1)
    raise ValueError("only PostgreSQL is supported")


class Database:
    def __init__(self, settings: Settings) -> None:
        database = settings.database
        self.engine: AsyncEngine = create_async_engine(
            async_database_url(database.url.get_secret_value()),
            pool_pre_ping=True,
            pool_size=database.pool_size,
            max_overflow=database.max_overflow,
            hide_parameters=True,
        )
        self.sessions = async_sessionmaker(self.engine, expire_on_commit=False)

    async def healthcheck(self) -> bool:
        try:
            async with self.engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
            return True
        except Exception:
            return False

    async def ensure_schema_current(self, alembic_ini: str | Path = "alembic.ini") -> None:
        config = Config(str(alembic_ini))
        expected = ScriptDirectory.from_config(config).get_current_head()
        async with self.engine.connect() as connection:
            current = await connection.scalar(text("SELECT version_num FROM alembic_version"))
        if current != expected:
            raise RuntimeError(f"database schema is {current!r}, expected {expected!r}; run alembic upgrade head")

    async def close(self) -> None:
        await self.engine.dispose()


class Repository:
    GROUP_FIELDS: ClassVar[dict[str, str]] = {
        "challenge_failed_action": "failed_action",
        "challenge_timeout_action": "timeout_action",
        "challenge_timeout": "timeout",
        "challenge_type": "challenge_type",
        "enable_global_blacklist": "global_blacklist",
    }

    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self.sessions = sessions

    async def get_blacklist_user(self, user_id: int) -> BlacklistRecord | None:
        async with self.sessions() as session:
            user = await session.get(BlacklistUser, user_id)
            if user is None:
                return None
            return BlacklistRecord(user.user_id, user.last_attempt, user.attempt_count)

    async def record_blacklist_timeout(self, when: datetime, user_id: int) -> None:
        statement = insert(BlacklistUser).values(user_id=user_id, last_attempt=when, attempt_count=1)
        statement = statement.on_conflict_do_update(
            index_elements=[BlacklistUser.user_id],
            set_={
                "last_attempt": when,
                "attempt_count": BlacklistUser.attempt_count + 1,
                "updated_at": datetime.now(),
            },
        )
        async with self.sessions.begin() as session:
            await session.execute(statement)

    async def record_auto_kick(self, user_id: int, when: datetime) -> int:
        statement = (
            update(BlacklistUser)
            .where(BlacklistUser.user_id == user_id)
            .values(
                last_attempt=when,
                attempt_count=BlacklistUser.attempt_count + 1,
                updated_at=datetime.now(),
            )
            .returning(BlacklistUser.attempt_count)
        )
        async with self.sessions.begin() as session:
            count = await session.scalar(statement)
        return int(count or 0)

    async def remove_blacklist_users(self, user_ids: int | Sequence[int]) -> None:
        ids = [user_ids] if isinstance(user_ids, int) else list(user_ids)
        if not ids:
            return
        async with self.sessions.begin() as session:
            await session.execute(delete(BlacklistUser).where(BlacklistUser.user_id.in_(ids)))

    async def all_blacklist_user_ids(self) -> list[int]:
        async with self.sessions() as session:
            return list(await session.scalars(select(BlacklistUser.user_id)))

    async def get_group_overrides(self, group_id: int) -> GroupOverrides | None:
        async with self.sessions() as session:
            group = await session.get(GroupConfig, group_id)
            if group is None:
                return None
            return GroupOverrides(
                challenge_timeout=group.timeout,
                challenge_timeout_action=FailedAction(group.timeout_action),
                challenge_failed_action=FailedAction(group.failed_action),
                challenge_type=ChallengeType(group.challenge_type),
                enable_global_blacklist=group.global_blacklist,
            )

    async def set_group_config(self, group_id: int, key: str, value: str, defaults: DefaultPolicy) -> None:
        normalized_key = key.lower()
        column_name = self.GROUP_FIELDS.get(normalized_key)
        if column_name is None:
            raise ValueError(f"不支持的配置项: {key}")
        parsed: int | str | bool
        if normalized_key == "challenge_timeout":
            parsed = int(value)
            if parsed <= 0:
                raise ValueError("challenge_timeout 必须为正整数")
        elif normalized_key in {"challenge_failed_action", "challenge_timeout_action"}:
            parsed = FailedAction(value.lower()).value
        elif normalized_key == "challenge_type":
            parsed = ChallengeType(value.lower()).value
        else:
            normalized = value.lower()
            if normalized not in {"0", "1", "true", "false"}:
                raise ValueError(f"{key} 必须为 0/1/true/false")
            parsed = normalized in {"1", "true"}
        base_values: dict[str, Any] = {
            "chat_id": group_id,
            "timeout": defaults.challenge_timeout,
            "challenge_type": defaults.challenge_type.value,
            "failed_action": defaults.challenge_failed_action.value,
            "timeout_action": defaults.challenge_timeout_action.value,
            "global_blacklist": defaults.enable_global_blacklist,
            column_name: parsed,
        }
        statement = insert(GroupConfig).values(**base_values)
        statement = statement.on_conflict_do_update(
            index_elements=[GroupConfig.chat_id],
            set_={column_name: parsed},
        )
        async with self.sessions.begin() as session:
            await session.execute(statement)

    async def log_recaptcha(
        self,
        challenge_id: str,
        user_id: int,
        chat_id: int,
        ip_addr: str,
        user_agent: str,
        action: RecaptchaLogAction,
    ) -> None:
        statement = insert(RecaptchaLog).values(
            challenge_id=challenge_id,
            user_id=user_id,
            group_id=chat_id,
            ip_addr=ip_addr,
            user_agent=user_agent,
            action=action.value,
        )
        statement = statement.on_conflict_do_nothing(constraint="uq_recaptcha_log_event")
        async with self.sessions.begin() as session:
            await session.execute(statement)

    @staticmethod
    def _to_log(row: RecaptchaLog) -> LogRecord:
        return LogRecord(
            row.group_id,
            row.user_id,
            row.challenge_id,
            row.ip_addr,
            row.user_agent,
            row.action,
            row.created_at,
        )

    async def _recent_logs(self, criterion: Any) -> list[LogRecord]:
        statement = select(RecaptchaLog).where(criterion).order_by(RecaptchaLog.created_at.desc()).limit(10)
        async with self.sessions() as session:
            rows = (await session.scalars(statement)).all()
        return [self._to_log(row) for row in rows]

    async def logs_by_challenge(self, challenge_id: str) -> list[LogRecord]:
        return await self._recent_logs(RecaptchaLog.challenge_id == challenge_id)

    async def logs_by_user(self, user_id: int) -> list[LogRecord]:
        return await self._recent_logs(RecaptchaLog.user_id == user_id)

    async def logs_by_ip(self, ip_addr: str) -> list[LogRecord]:
        return await self._recent_logs(RecaptchaLog.ip_addr == ip_addr)

    async def passed_users_by_ip(self, ip_addr: str) -> list[tuple[int, int, datetime | None]]:
        last_passed_at = func.max(RecaptchaLog.created_at).label("last_passed_at")
        statement = (
            select(RecaptchaLog.group_id, RecaptchaLog.user_id, last_passed_at)
            .where(RecaptchaLog.ip_addr == ip_addr, RecaptchaLog.action == RecaptchaLogAction.PASSED.value)
            .group_by(RecaptchaLog.group_id, RecaptchaLog.user_id)
            .order_by(last_passed_at.desc())
        )
        async with self.sessions() as session:
            rows = (await session.execute(statement)).all()
        return [(row.group_id, row.user_id, row.last_passed_at) for row in rows]

    async def passed_user_ids_by_ip_and_group(self, ip_addr: str, group_id: int) -> list[int]:
        statement = (
            select(RecaptchaLog.user_id)
            .where(
                RecaptchaLog.ip_addr == ip_addr,
                RecaptchaLog.group_id == group_id,
                RecaptchaLog.action == RecaptchaLogAction.PASSED.value,
            )
            .distinct()
        )
        async with self.sessions() as session:
            return list(await session.scalars(statement))
