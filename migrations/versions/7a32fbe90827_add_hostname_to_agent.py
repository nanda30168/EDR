"""Add hostname to Agent

Revision ID: 7a32fbe90827
Revises: None
Create Date: 2025-03-19 05:38:27.123456

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7a32fbe90827'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('agent', schema=None) as batch_op:
        batch_op.add_column(sa.Column('hostname', sa.String(length=255), nullable=False))
        batch_op.create_unique_constraint('uq_agent_hostname', ['hostname'])  # Ensure the constraint has a name


def downgrade():
    with op.batch_alter_table('agent', schema=None) as batch_op:
        batch_op.drop_constraint('uq_agent_hostname', type_='unique')
        batch_op.drop_column('hostname')