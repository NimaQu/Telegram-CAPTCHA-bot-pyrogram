"""add per-group guest bot block switch

Revision ID: 9c3e5f7a1b24
Revises: 5a1f3c7e9b42
Create Date: 2026-11-20
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "9c3e5f7a1b24"
down_revision: str | None = "5a1f3c7e9b42"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("group_config") as batch_op:
        batch_op.add_column(sa.Column("guest_bot_block", sa.Boolean(), nullable=False, server_default="1"))


def downgrade() -> None:
    with op.batch_alter_table("group_config") as batch_op:
        batch_op.drop_column("guest_bot_block")
