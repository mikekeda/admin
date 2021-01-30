"""Add Repo.coverage column.

Revision ID: 746c27cbb1aa
Revises: eba082f5c48f
Create Date: 2021-01-30 10:08:37.141042

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '746c27cbb1aa'
down_revision = 'eba082f5c48f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('repos', sa.Column('coverage', sa.String(length=128), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('repos', 'coverage')
    # ### end Alembic commands ###
