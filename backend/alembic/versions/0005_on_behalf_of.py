"""on-behalf-of human authority anchor (Slice 11)

Revision ID: 0005_on_behalf_of
Revises: 0004_oauth_clients
Create Date: 2026-09-14 00:00:00.000000+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '0005_on_behalf_of'
down_revision: Union[str, None] = '0004_oauth_clients'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('agents', sa.Column('activated_by_user_id', sa.String(), nullable=True))
    op.create_index(
        op.f('ix_agents_activated_by_user_id'), 'agents', ['activated_by_user_id'], unique=False
    )
    op.create_foreign_key(
        'agents_activated_by_user_id_fkey', 'agents', 'users', ['activated_by_user_id'], ['id']
    )

    op.create_table(
        'on_behalf_of_grants',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), nullable=False),
        sa.Column('agent_id', sa.String(), nullable=False),
        sa.Column('granted_by_user_id', sa.String(), nullable=False),
        sa.Column('scopes', sa.ARRAY(sa.String()), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revocation_reason', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['agent_id'], ['agents.id']),
        sa.ForeignKeyConstraint(['granted_by_user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_on_behalf_of_grants_org_id'), 'on_behalf_of_grants', ['org_id'], unique=False)
    op.create_index(op.f('ix_on_behalf_of_grants_agent_id'), 'on_behalf_of_grants', ['agent_id'], unique=False)
    op.create_index(
        op.f('ix_on_behalf_of_grants_granted_by_user_id'), 'on_behalf_of_grants', ['granted_by_user_id'], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f('ix_on_behalf_of_grants_granted_by_user_id'), table_name='on_behalf_of_grants')
    op.drop_index(op.f('ix_on_behalf_of_grants_agent_id'), table_name='on_behalf_of_grants')
    op.drop_index(op.f('ix_on_behalf_of_grants_org_id'), table_name='on_behalf_of_grants')
    op.drop_table('on_behalf_of_grants')

    op.drop_constraint('agents_activated_by_user_id_fkey', 'agents', type_='foreignkey')
    op.drop_index(op.f('ix_agents_activated_by_user_id'), table_name='agents')
    op.drop_column('agents', 'activated_by_user_id')
