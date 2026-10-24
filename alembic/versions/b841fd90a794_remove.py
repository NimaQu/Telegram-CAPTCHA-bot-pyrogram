"""remove

Revision ID: b841fd90a794
Revises: c945fe00daeb
Create Date: 2024-05-08 02:19:02.253873

"""

from collections.abc import Sequence

# revision identifiers, used by Alembic.
revision: str = "b841fd90a794"
down_revision: str | None = "c945fe00daeb"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # The foreign key was removed from the base revision. Existing databases
    # that already applied this revision are unchanged.
    pass


def downgrade() -> None:
    pass
