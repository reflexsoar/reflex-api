"""empty message

Revision ID: 1da246e2589b
Revises: 7001a1dd4831
Create Date: 2020-10-02 20:13:49.841422

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1da246e2589b'
down_revision = '7001a1dd4831'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('global_settings', sa.Column('allow_event_deletion', sa.Boolean(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('global_settings', 'allow_event_deletion')
    # ### end Alembic commands ###
