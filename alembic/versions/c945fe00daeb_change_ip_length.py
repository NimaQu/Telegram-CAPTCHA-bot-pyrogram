"""change_ip_length

Revision ID: c945fe00daeb
Revises: 13a9421b19d9
Create Date: 2024-05-04 03:30:17.311752

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c945fe00daeb'
down_revision: Union[str, None] = '13a9421b19d9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_unique_constraint(None, 'blacklist_user', ['user_id'])
    op.create_unique_constraint(None, 'group_config', ['chat_id'])
    op.alter_column('recaptcha_log', 'ip_addr',
               existing_type=sa.VARCHAR(length=15),
               type_=sa.String(length=64),
               existing_nullable=False)
    op.create_unique_constraint(None, 'recaptcha_log', ['id'])
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'recaptcha_log', type_='unique')
    op.alter_column('recaptcha_log', 'ip_addr',
               existing_type=sa.String(length=64),
               type_=sa.VARCHAR(length=15),
               existing_nullable=False)
    op.drop_constraint(None, 'group_config', type_='unique')
    op.drop_constraint(None, 'blacklist_user', type_='unique')
    # ### end Alembic commands ###