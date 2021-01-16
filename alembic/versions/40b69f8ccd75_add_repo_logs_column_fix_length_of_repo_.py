"""Add Repo.logs column. Fix length of Repo.title and Repo.name.

Revision ID: 40b69f8ccd75
Revises: d011e7ca4105
Create Date: 2021-01-16 10:21:39.695757

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '40b69f8ccd75'
down_revision = 'd011e7ca4105'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('repos', sa.Column('logs', sa.ARRAY(sa.String(length=32)), nullable=True))
    op.alter_column('repos', 'name',
               existing_type=sa.VARCHAR(length=32),
               type_=sa.String(length=64),
               existing_nullable=False)
    op.alter_column('repos', 'title',
               existing_type=sa.VARCHAR(length=32),
               type_=sa.String(length=64),
               existing_nullable=False)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('repos', 'title',
               existing_type=sa.String(length=64),
               type_=sa.VARCHAR(length=32),
               existing_nullable=False)
    op.alter_column('repos', 'name',
               existing_type=sa.String(length=64),
               type_=sa.VARCHAR(length=32),
               existing_nullable=False)
    op.drop_column('repos', 'logs')
    # ### end Alembic commands ###
