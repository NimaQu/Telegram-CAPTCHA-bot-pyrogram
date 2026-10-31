"""add antispam tables

Revision ID: 3d6e8b1f0a27
Revises: 7f4c2a9d5e10
Create Date: 2026-10-31
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "3d6e8b1f0a27"
down_revision: str | None = "7f4c2a9d5e10"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "antispam_config",
        sa.Column("chat_id", sa.BigInteger(), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("api_key_encrypted", sa.Text()),
        sa.Column("key_last4", sa.String(8)),
        sa.Column("key_set_by", sa.BigInteger()),
        sa.Column("key_set_by_name", sa.String(128)),
        sa.Column("key_set_at", sa.DateTime()),
        sa.Column("disabled_reason", sa.Text()),
        sa.Column("disabled_at", sa.DateTime()),
        sa.Column("failure_count", sa.Integer(), nullable=False),
        sa.Column("first_failure_at", sa.DateTime()),
        sa.Column("classifiers", sa.Text(), nullable=False),
        sa.Column("action", sa.String(10), nullable=False),
        sa.Column("act_threshold", sa.Integer(), nullable=False),
        sa.Column("log_threshold", sa.Integer(), nullable=False),
        sa.Column("daily_limit", sa.Integer(), nullable=False),
        sa.Column("rules", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime()),
        sa.CheckConstraint("action IN ('delete', 'mute', 'kick', 'ban')", name="ck_antispam_config_action"),
        sa.CheckConstraint("act_threshold BETWEEN 1 AND 100", name="ck_antispam_config_act_threshold"),
        sa.CheckConstraint("log_threshold BETWEEN 0 AND 100", name="ck_antispam_config_log_threshold"),
        sa.CheckConstraint("daily_limit > 0", name="ck_antispam_config_daily_limit"),
    )
    op.create_table(
        "antispam_pending",
        sa.Column("chat_id", sa.BigInteger(), primary_key=True),
        sa.Column("user_id", sa.BigInteger(), primary_key=True),
        sa.Column("passed_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "antispam_usage",
        sa.Column("chat_id", sa.BigInteger(), primary_key=True),
        sa.Column("day", sa.Date(), primary_key=True),
        sa.Column("calls", sa.Integer(), nullable=False),
        sa.Column("input_tokens", sa.BigInteger(), nullable=False),
        sa.Column("limit_notified", sa.Boolean(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("antispam_usage")
    op.drop_table("antispam_pending")
    op.drop_table("antispam_config")
