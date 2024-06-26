"""remove

Revision ID: b841fd90a794
Revises: c945fe00daeb
Create Date: 2024-05-08 02:19:02.253873

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b841fd90a794'
down_revision: Union[str, None] = 'c945fe00daeb'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint('recaptcha_log_group_id_fkey', 'recaptcha_log', type_='foreignkey')
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_foreign_key('recaptcha_log_group_id_fkey', 'recaptcha_log', 'group_config', ['group_id'], ['chat_id'])
    # ### end Alembic commands ###
