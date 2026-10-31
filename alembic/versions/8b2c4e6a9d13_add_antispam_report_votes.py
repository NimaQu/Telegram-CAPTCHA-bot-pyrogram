"""add antispam report votes

Revision ID: 8b2c4e6a9d13
Revises: 3d6e8b1f0a27
Create Date: 2026-10-31
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "8b2c4e6a9d13"
down_revision: str | None = "3d6e8b1f0a27"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("antispam_config") as batch_op:
        batch_op.add_column(sa.Column("report_votes", sa.Integer(), nullable=False, server_default="3"))
        batch_op.create_check_constraint("ck_antispam_config_report_votes", "report_votes BETWEEN 0 AND 20")


def downgrade() -> None:
    with op.batch_alter_table("antispam_config") as batch_op:
        batch_op.drop_constraint("ck_antispam_config_report_votes", type_="check")
        batch_op.drop_column("report_votes")
