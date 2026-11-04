"""add IP block rules and per-group IP reputation switch

Revision ID: 5a1f3c7e9b42
Revises: 8b2c4e6a9d13
Create Date: 2026-11-04
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "5a1f3c7e9b42"
down_revision: str | None = "8b2c4e6a9d13"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ip_block_rule",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(8), nullable=False),
        sa.Column("value", sa.String(64), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("created_by", sa.BigInteger()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("hits", sa.Integer(), nullable=False),
        sa.Column("last_hit_at", sa.DateTime()),
        sa.UniqueConstraint("kind", "value", name="uq_ip_block_rule_kind_value"),
        sa.CheckConstraint("kind IN ('cidr', 'asn')", name="ck_ip_block_rule_kind"),
    )
    with op.batch_alter_table("group_config") as batch_op:
        batch_op.add_column(sa.Column("ip_reputation", sa.Boolean(), nullable=False, server_default="1"))


def downgrade() -> None:
    with op.batch_alter_table("group_config") as batch_op:
        batch_op.drop_column("ip_reputation")
    op.drop_table("ip_block_rule")
