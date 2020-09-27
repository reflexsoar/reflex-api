"""empty message

Revision ID: 2839eb0f2fad
Revises: 26a6a5e2bc85
Create Date: 2020-09-27 00:19:34.007934

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2839eb0f2fad'
down_revision = '26a6a5e2bc85'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('permission', sa.Column('create_event_rule', sa.Boolean(), nullable=True))
    op.add_column('permission', sa.Column('delete_event_rule', sa.Boolean(), nullable=True))
    op.add_column('permission', sa.Column('update_event_rule', sa.Boolean(), nullable=True))
    op.add_column('permission', sa.Column('view_event_rules', sa.Boolean(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('permission', 'view_event_rules')
    op.drop_column('permission', 'update_event_rule')
    op.drop_column('permission', 'delete_event_rule')
    op.drop_column('permission', 'create_event_rule')
    # ### end Alembic commands ###
