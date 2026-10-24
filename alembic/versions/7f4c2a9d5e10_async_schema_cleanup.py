"""async schema cleanup

Revision ID: 7f4c2a9d5e10
Revises: b841fd90a794
Create Date: 2026-07-14
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "7f4c2a9d5e10"
down_revision: str | None = "b841fd90a794"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if op.get_bind().dialect.name != "sqlite":
        op.drop_constraint("blacklist_user_user_id_key", "blacklist_user", type_="unique", if_exists=True)
        op.drop_constraint("group_config_chat_id_key", "group_config", type_="unique", if_exists=True)
        op.drop_constraint("recaptcha_log_id_key", "recaptcha_log", type_="unique", if_exists=True)

    op.execute("UPDATE group_config SET timeout = 300 WHERE timeout <= 0")
    op.execute("UPDATE group_config SET challenge_type = 'math' WHERE challenge_type NOT IN ('math', 'recaptcha')")
    op.execute("UPDATE group_config SET failed_action = 'kick' WHERE failed_action NOT IN ('ban', 'kick')")
    op.execute("UPDATE group_config SET timeout_action = 'kick' WHERE timeout_action NOT IN ('ban', 'kick')")
    with op.batch_alter_table("group_config") as batch_op:
        batch_op.drop_column("third_party_blacklist")
        batch_op.create_check_constraint("ck_group_config_timeout_positive", "timeout > 0")
        batch_op.create_check_constraint("ck_group_config_challenge_type", "challenge_type IN ('math', 'recaptcha')")
        batch_op.create_check_constraint("ck_group_config_failed_action", "failed_action IN ('ban', 'kick')")
        batch_op.create_check_constraint("ck_group_config_timeout_action", "timeout_action IN ('ban', 'kick')")
    with op.batch_alter_table("recaptcha_log") as batch_op:
        batch_op.create_unique_constraint(
            "uq_recaptcha_log_event", ["challenge_id", "user_id", "group_id", "ip_addr", "action"]
        )
    op.create_index("ix_recaptcha_log_challenge_created", "recaptcha_log", ["challenge_id", "created_at"])
    op.create_index("ix_recaptcha_log_user_created", "recaptcha_log", ["user_id", "created_at"])
    op.create_index(
        "ix_recaptcha_log_ip_action_group_user_created",
        "recaptcha_log",
        ["ip_addr", "action", "group_id", "user_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_recaptcha_log_ip_action_group_user_created", table_name="recaptcha_log")
    op.drop_index("ix_recaptcha_log_user_created", table_name="recaptcha_log")
    op.drop_index("ix_recaptcha_log_challenge_created", table_name="recaptcha_log")
    with op.batch_alter_table("recaptcha_log") as batch_op:
        batch_op.drop_constraint("uq_recaptcha_log_event", type_="unique")
    with op.batch_alter_table("group_config") as batch_op:
        batch_op.drop_constraint("ck_group_config_timeout_action", type_="check")
        batch_op.drop_constraint("ck_group_config_failed_action", type_="check")
        batch_op.drop_constraint("ck_group_config_challenge_type", type_="check")
        batch_op.drop_constraint("ck_group_config_timeout_positive", type_="check")
        batch_op.add_column(sa.Column("third_party_blacklist", sa.Boolean(), nullable=False, server_default=sa.false()))
    if op.get_bind().dialect.name != "sqlite":
        op.create_unique_constraint("recaptcha_log_id_key", "recaptcha_log", ["id"])
        op.create_unique_constraint("group_config_chat_id_key", "group_config", ["chat_id"])
        op.create_unique_constraint("blacklist_user_user_id_key", "blacklist_user", ["user_id"])
