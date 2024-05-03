"""init

Revision ID: e3a2c7dbec4e
Revises: 
Create Date: 2024-05-03 02:09:46.141525

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e3a2c7dbec4e'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('blacklist_user',
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('last_attempt', sa.DateTime(), nullable=False),
    sa.Column('attempt_count', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('user_id'),
    sa.UniqueConstraint('user_id')
    )
    op.create_table('group_config',
    sa.Column('chat_id', sa.BigInteger(), nullable=False),
    sa.Column('timeout', sa.Integer(), nullable=False),
    sa.Column('challenge_type', sa.String(length=10), nullable=False),
    sa.Column('failed_action', sa.String(length=10), nullable=False),
    sa.Column('timeout_action', sa.String(length=10), nullable=False),
    sa.Column('third_party_blacklist', sa.Boolean(), nullable=False),
    sa.Column('global_blacklist', sa.Boolean(), nullable=False),
    sa.PrimaryKeyConstraint('chat_id'),
    sa.UniqueConstraint('chat_id')
    )
    op.create_table('recaptcha_log',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('group_id', sa.BigInteger(), nullable=False),
    sa.Column('user_id', sa.BigInteger(), nullable=False),
    sa.Column('ip_addr', sa.String(length=15), nullable=False),
    sa.Column('user_agent', sa.Text(), nullable=False),
    sa.Column('action', sa.String(length=20), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['group_id'], ['group_config.chat_id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('recaptcha_log')
    op.drop_table('group_config')
    op.drop_table('blacklist_user')
    # ### end Alembic commands ###
