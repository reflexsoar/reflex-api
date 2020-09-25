"""empty message

Revision ID: 51cad272d821
Revises: 01510000707f
Create Date: 2020-09-24 21:56:02.837607

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '51cad272d821'
down_revision = '01510000707f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('case', sa.Column('close_comment', sa.String(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('case', 'close_comment')
    # ### end Alembic commands ###
