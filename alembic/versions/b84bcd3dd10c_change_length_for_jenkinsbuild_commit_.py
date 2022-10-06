"""Change length for JenkinsBuild:commit_message column (80 -> 120)

Revision ID: b84bcd3dd10c
Revises: 7adf58c84d91
Create Date: 2022-09-30 16:59:54.070453

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b84bcd3dd10c'
down_revision = '7adf58c84d91'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('jenkins_builds', 'commit_message',
               existing_type=sa.VARCHAR(length=80),
               type_=sa.String(length=120),
               existing_nullable=True)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('jenkins_builds', 'commit_message',
               existing_type=sa.String(length=120),
               type_=sa.VARCHAR(length=80),
               existing_nullable=True)
    # ### end Alembic commands ###
