from __future__ import annotations

from datetime import date, datetime
from enum import StrEnum

from sqlalchemy import BigInteger, CheckConstraint, Date, DateTime, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class RecaptchaLogAction(StrEnum):
    PAGE_VISIT = "PageVisit"
    FAILED = "Failed"
    PASSED = "Passed"


class BlacklistUser(Base):
    __tablename__ = "blacklist_user"

    user_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    last_attempt: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.now)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime | None] = mapped_column(DateTime, default=datetime.now)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime, default=datetime.now, onupdate=datetime.now)


class GroupConfig(Base):
    __tablename__ = "group_config"
    __table_args__ = (
        CheckConstraint("timeout > 0", name="ck_group_config_timeout_positive"),
        CheckConstraint("challenge_type IN ('math', 'recaptcha')", name="ck_group_config_challenge_type"),
        CheckConstraint("failed_action IN ('ban', 'kick')", name="ck_group_config_failed_action"),
        CheckConstraint("timeout_action IN ('ban', 'kick')", name="ck_group_config_timeout_action"),
    )

    chat_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    timeout: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    challenge_type: Mapped[str] = mapped_column(String(10), nullable=False, default="recaptcha")
    failed_action: Mapped[str] = mapped_column(String(10), nullable=False, default="kick")
    timeout_action: Mapped[str] = mapped_column(String(10), nullable=False, default="kick")
    global_blacklist: Mapped[bool] = mapped_column(nullable=False, default=True)


class RecaptchaLog(Base):
    __tablename__ = "recaptcha_log"
    __table_args__ = (
        UniqueConstraint(
            "challenge_id",
            "user_id",
            "group_id",
            "ip_addr",
            "action",
            name="uq_recaptcha_log_event",
        ),
        Index("ix_recaptcha_log_challenge_created", "challenge_id", "created_at"),
        Index("ix_recaptcha_log_user_created", "user_id", "created_at"),
        Index(
            "ix_recaptcha_log_ip_action_group_user_created",
            "ip_addr",
            "action",
            "group_id",
            "user_id",
            "created_at",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    user_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    challenge_id: Mapped[str] = mapped_column(String(64), nullable=False)
    ip_addr: Mapped[str] = mapped_column(String(64), nullable=False)
    user_agent: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[str] = mapped_column(String(20), nullable=False)
    created_at: Mapped[datetime | None] = mapped_column(DateTime, default=datetime.now)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime, default=datetime.now, onupdate=datetime.now)


class AntispamConfig(Base):
    __tablename__ = "antispam_config"
    __table_args__ = (
        CheckConstraint("action IN ('delete', 'mute', 'kick', 'ban')", name="ck_antispam_config_action"),
        CheckConstraint("act_threshold BETWEEN 1 AND 100", name="ck_antispam_config_act_threshold"),
        CheckConstraint("log_threshold BETWEEN 0 AND 100", name="ck_antispam_config_log_threshold"),
        CheckConstraint("daily_limit > 0", name="ck_antispam_config_daily_limit"),
    )

    chat_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    enabled: Mapped[bool] = mapped_column(nullable=False, default=False)
    # Fernet 加密后的 token，永远不会返回给 Mini App
    api_key_encrypted: Mapped[str | None] = mapped_column(Text)
    key_last4: Mapped[str | None] = mapped_column(String(8))
    key_set_by: Mapped[int | None] = mapped_column(BigInteger)
    key_set_by_name: Mapped[str | None] = mapped_column(String(128))
    key_set_at: Mapped[datetime | None] = mapped_column(DateTime)
    disabled_reason: Mapped[str | None] = mapped_column(Text)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime)
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    first_failure_at: Mapped[datetime | None] = mapped_column(DateTime)
    classifiers: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    action: Mapped[str] = mapped_column(String(10), nullable=False, default="mute")
    act_threshold: Mapped[int] = mapped_column(Integer, nullable=False, default=85)
    log_threshold: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    daily_limit: Mapped[int] = mapped_column(Integer, nullable=False, default=500)
    rules: Mapped[str] = mapped_column(Text, nullable=False, default="")
    updated_at: Mapped[datetime | None] = mapped_column(DateTime, default=datetime.now, onupdate=datetime.now)


class AntispamPending(Base):
    """通过验证、但还没在群里发过言的新成员；第一条消息送检后删除。"""

    __tablename__ = "antispam_pending"

    chat_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    user_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    passed_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.now)


class AntispamUsage(Base):
    __tablename__ = "antispam_usage"

    chat_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    day: Mapped[date] = mapped_column(Date, primary_key=True)
    calls: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    input_tokens: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    limit_notified: Mapped[bool] = mapped_column(nullable=False, default=False)
