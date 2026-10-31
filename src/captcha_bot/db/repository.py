from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import delete, event, func, inspect, select, text, update
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from captcha_bot.config import ChallengeType, DefaultPolicy, FailedAction, Settings
from captcha_bot.db.models import (
    AntispamConfig,
    AntispamPending,
    AntispamUsage,
    BlacklistUser,
    GroupConfig,
    RecaptchaLog,
    RecaptchaLogAction,
)


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

    def format(self, ip_text: str) -> str:
        return f"IP地址: {ip_text}\nUA：`{self.user_agent}`\n状态：`{self.action}`\n时间：`{self.created_at}`\n"

    def __str__(self) -> str:
        return self.format(f"`{self.ip_addr}`")


@dataclass(frozen=True, slots=True)
class AntispamRecord:
    chat_id: int
    enabled: bool
    api_key_encrypted: str | None
    key_last4: str | None
    key_set_by: int | None
    key_set_by_name: str | None
    key_set_at: datetime | None
    disabled_reason: str | None
    disabled_at: datetime | None
    classifiers: str
    action: str
    act_threshold: int
    log_threshold: int
    daily_limit: int
    rules: str
    report_votes: int


@dataclass(frozen=True, slots=True)
class AntispamRules:
    classifiers: str
    action: str
    act_threshold: int
    log_threshold: int
    daily_limit: int
    rules: str
    report_votes: int = 3


@dataclass(frozen=True, slots=True)
class AntispamKeyOwner:
    user_id: int | None
    encrypted: str | None


@dataclass(frozen=True, slots=True)
class UsageSummary:
    today_calls: int
    today_tokens: int
    month_calls: int
    month_tokens: int


def async_database_url(url: str) -> str:
    if url.startswith("sqlite+aiosqlite:///"):
        return url
    if url.startswith("sqlite:///"):
        return url.replace("sqlite:///", "sqlite+aiosqlite:///", 1)
    raise ValueError("only SQLite is supported")


class Database:
    def __init__(self, settings: Settings) -> None:
        database = settings.database
        busy_timeout_ms = database.busy_timeout_ms
        self.engine: AsyncEngine = create_async_engine(
            async_database_url(database.url),
            pool_pre_ping=True,
            pool_size=1,
            max_overflow=0,
            connect_args={"timeout": busy_timeout_ms / 1000},
            hide_parameters=True,
        )

        @event.listens_for(self.engine.sync_engine, "connect")
        def configure_sqlite_connection(dbapi_connection: Any, _: Any) -> None:
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
            finally:
                cursor.close()

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
        initialize_hint = "uv run captcha-bot init-db --config config.toml (use your actual config path)"
        try:
            async with self.engine.connect() as connection:
                has_version = await connection.run_sync(lambda sync: inspect(sync).has_table("alembic_version"))
                if not has_version:
                    raise RuntimeError(f"database schema is not initialized; run {initialize_hint}")
                current = await connection.scalar(text("SELECT version_num FROM alembic_version"))
        except SQLAlchemyError as exc:
            raise RuntimeError(
                "cannot read database schema; check the database path, permissions and file integrity"
            ) from exc
        if current != expected:
            raise RuntimeError(f"database schema is {current!r}, expected {expected!r}; run {initialize_hint}")

    async def close(self) -> None:
        await self.engine.dispose()


class Repository:
    # Stay below SQLite's historical default of 999 bound variables per statement.
    DELETE_BATCH_SIZE: ClassVar[int] = 500
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
            for offset in range(0, len(ids), self.DELETE_BATCH_SIZE):
                batch = ids[offset : offset + self.DELETE_BATCH_SIZE]
                await session.execute(delete(BlacklistUser).where(BlacklistUser.user_id.in_(batch)))

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

    async def save_group_overrides(self, group_id: int, overrides: GroupOverrides) -> None:
        values: dict[str, Any] = {
            "timeout": overrides.challenge_timeout,
            "challenge_type": overrides.challenge_type.value,
            "failed_action": overrides.challenge_failed_action.value,
            "timeout_action": overrides.challenge_timeout_action.value,
            "global_blacklist": overrides.enable_global_blacklist,
        }
        statement = insert(GroupConfig).values(chat_id=group_id, **values)
        statement = statement.on_conflict_do_update(index_elements=[GroupConfig.chat_id], set_=values)
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
        statement = statement.on_conflict_do_nothing(
            index_elements=[
                RecaptchaLog.challenge_id,
                RecaptchaLog.user_id,
                RecaptchaLog.group_id,
                RecaptchaLog.ip_addr,
                RecaptchaLog.action,
            ]
        )
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

    # ---- 反垃圾 ----

    @staticmethod
    def _to_antispam(row: AntispamConfig) -> AntispamRecord:
        return AntispamRecord(
            chat_id=row.chat_id,
            enabled=row.enabled,
            api_key_encrypted=row.api_key_encrypted,
            key_last4=row.key_last4,
            key_set_by=row.key_set_by,
            key_set_by_name=row.key_set_by_name,
            key_set_at=row.key_set_at,
            disabled_reason=row.disabled_reason,
            disabled_at=row.disabled_at,
            classifiers=row.classifiers,
            action=row.action,
            act_threshold=row.act_threshold,
            log_threshold=row.log_threshold,
            daily_limit=row.daily_limit,
            rules=row.rules,
            report_votes=row.report_votes,
        )

    async def get_antispam(self, chat_id: int) -> AntispamRecord | None:
        async with self.sessions() as session:
            row = await session.get(AntispamConfig, chat_id)
            return None if row is None else self._to_antispam(row)

    async def _ensure_antispam_row(self, session: AsyncSession, chat_id: int, defaults: AntispamRules) -> None:
        statement = insert(AntispamConfig).values(
            chat_id=chat_id,
            enabled=False,
            failure_count=0,
            classifiers=defaults.classifiers,
            action=defaults.action,
            act_threshold=defaults.act_threshold,
            log_threshold=defaults.log_threshold,
            daily_limit=defaults.daily_limit,
            rules=defaults.rules,
            report_votes=defaults.report_votes,
        )
        await session.execute(statement.on_conflict_do_nothing(index_elements=[AntispamConfig.chat_id]))

    async def save_antispam_rules(self, chat_id: int, rules: AntispamRules) -> None:
        async with self.sessions.begin() as session:
            await self._ensure_antispam_row(session, chat_id, rules)
            await session.execute(
                update(AntispamConfig)
                .where(AntispamConfig.chat_id == chat_id)
                .values(
                    classifiers=rules.classifiers,
                    action=rules.action,
                    act_threshold=rules.act_threshold,
                    log_threshold=rules.log_threshold,
                    daily_limit=rules.daily_limit,
                    rules=rules.rules,
                    report_votes=rules.report_votes,
                    updated_at=datetime.now(),
                )
            )

    async def set_antispam_key(
        self,
        chat_id: int,
        *,
        encrypted: str | None,
        last4: str | None,
        user_id: int | None,
        user_name: str | None,
        defaults: AntispamRules,
    ) -> AntispamKeyOwner:
        """设置(或清除) token，返回之前的设置者。设置新 token 视为一次手动开启。"""
        async with self.sessions.begin() as session:
            await self._ensure_antispam_row(session, chat_id, defaults)
            row = await session.get(AntispamConfig, chat_id)
            assert row is not None
            previous = AntispamKeyOwner(row.key_set_by, row.api_key_encrypted)
            row.api_key_encrypted = encrypted
            row.key_last4 = last4
            row.key_set_by = user_id
            row.key_set_by_name = user_name
            row.key_set_at = datetime.now() if encrypted else None
            row.enabled = encrypted is not None
            row.disabled_reason = None
            row.disabled_at = None
            row.failure_count = 0
            row.first_failure_at = None
        return previous

    async def set_antispam_enabled(self, chat_id: int, enabled: bool) -> None:
        values: dict[str, Any] = {"enabled": enabled, "failure_count": 0, "first_failure_at": None}
        if enabled:
            values |= {"disabled_reason": None, "disabled_at": None}
        async with self.sessions.begin() as session:
            await session.execute(update(AntispamConfig).where(AntispamConfig.chat_id == chat_id).values(**values))

    async def disable_antispam(self, chat_id: int, reason: str, when: datetime) -> bool:
        """自动关闭；只有本次调用真正把开关从开改成关时返回 True，避免重复通知。"""
        statement = (
            update(AntispamConfig)
            .where(AntispamConfig.chat_id == chat_id, AntispamConfig.enabled.is_(True))
            .values(enabled=False, disabled_reason=reason, disabled_at=when, failure_count=0, first_failure_at=None)
            .returning(AntispamConfig.chat_id)
        )
        async with self.sessions.begin() as session:
            return await session.scalar(statement) is not None

    async def record_antispam_failure(self, chat_id: int, when: datetime) -> tuple[int, datetime]:
        statement = (
            update(AntispamConfig)
            .where(AntispamConfig.chat_id == chat_id)
            .values(
                failure_count=AntispamConfig.failure_count + 1,
                first_failure_at=func.coalesce(AntispamConfig.first_failure_at, when),
            )
            .returning(AntispamConfig.failure_count, AntispamConfig.first_failure_at)
        )
        async with self.sessions.begin() as session:
            row = (await session.execute(statement)).one_or_none()
        if row is None:
            return 0, when
        return int(row.failure_count), row.first_failure_at or when

    async def reset_antispam_failures(self, chat_id: int) -> None:
        async with self.sessions.begin() as session:
            await session.execute(
                update(AntispamConfig)
                .where(AntispamConfig.chat_id == chat_id, AntispamConfig.failure_count > 0)
                .values(failure_count=0, first_failure_at=None)
            )

    async def add_antispam_pending(self, chat_id: int, user_id: int, when: datetime) -> None:
        statement = insert(AntispamPending).values(chat_id=chat_id, user_id=user_id, passed_at=when)
        statement = statement.on_conflict_do_update(
            index_elements=[AntispamPending.chat_id, AntispamPending.user_id], set_={"passed_at": when}
        )
        async with self.sessions.begin() as session:
            await session.execute(statement)

    async def pop_antispam_pending(self, chat_id: int, user_id: int, max_age: timedelta) -> bool:
        statement = (
            delete(AntispamPending)
            .where(AntispamPending.chat_id == chat_id, AntispamPending.user_id == user_id)
            .returning(AntispamPending.passed_at)
        )
        async with self.sessions.begin() as session:
            passed_at = await session.scalar(statement)
            # 顺手清理一直没发言的旧记录
            await session.execute(delete(AntispamPending).where(AntispamPending.passed_at < datetime.now() - max_age))
        return passed_at is not None and datetime.now() - passed_at <= max_age

    async def add_antispam_usage(self, chat_id: int, day: date, input_tokens: int) -> None:
        statement = insert(AntispamUsage).values(
            chat_id=chat_id, day=day, calls=1, input_tokens=input_tokens, limit_notified=False
        )
        statement = statement.on_conflict_do_update(
            index_elements=[AntispamUsage.chat_id, AntispamUsage.day],
            set_={
                "calls": AntispamUsage.calls + 1,
                "input_tokens": AntispamUsage.input_tokens + input_tokens,
            },
        )
        async with self.sessions.begin() as session:
            await session.execute(statement)

    async def antispam_calls(self, chat_id: int, day: date) -> int:
        async with self.sessions() as session:
            row = await session.get(AntispamUsage, (chat_id, day))
            return 0 if row is None else row.calls

    async def mark_antispam_limit_notified(self, chat_id: int, day: date) -> bool:
        statement = (
            update(AntispamUsage)
            .where(
                AntispamUsage.chat_id == chat_id,
                AntispamUsage.day == day,
                AntispamUsage.limit_notified.is_(False),
            )
            .values(limit_notified=True)
            .returning(AntispamUsage.chat_id)
        )
        async with self.sessions.begin() as session:
            return await session.scalar(statement) is not None

    async def antispam_usage(self, chat_id: int, today: date) -> UsageSummary:
        month_start = today.replace(day=1)
        statement = select(AntispamUsage).where(AntispamUsage.chat_id == chat_id, AntispamUsage.day >= month_start)
        async with self.sessions() as session:
            rows = (await session.scalars(statement)).all()
        today_rows = [row for row in rows if row.day == today]
        return UsageSummary(
            today_calls=sum(row.calls for row in today_rows),
            today_tokens=sum(row.input_tokens for row in today_rows),
            month_calls=sum(row.calls for row in rows),
            month_tokens=sum(row.input_tokens for row in rows),
        )
