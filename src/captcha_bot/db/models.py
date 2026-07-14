from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from sqlalchemy import BigInteger, CheckConstraint, DateTime, Index, Integer, String, Text, UniqueConstraint
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
