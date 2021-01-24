"""Replased Repo.logs column with Repo.processes

Revision ID: eba082f5c48f
Revises: 40b69f8ccd75
Create Date: 2021-01-24 11:47:03.576583

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'eba082f5c48f'
down_revision = '40b69f8ccd75'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('repos', sa.Column('processes', sa.ARRAY(sa.Boolean()), server_default='{}', nullable=True))
    op.drop_column('repos', 'logs')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('repos', sa.Column('logs', postgresql.ARRAY(sa.VARCHAR(length=32)), autoincrement=False, nullable=True))
    op.drop_column('repos', 'processes')
    # ### end Alembic commands ###
