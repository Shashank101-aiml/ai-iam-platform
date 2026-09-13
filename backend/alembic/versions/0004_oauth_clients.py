"""oauth clients (Dynamic Client Registration, RFC 7591)

Revision ID: 0004_oauth_clients
Revises: 0003_audit_log_durability
Create Date: 2026-09-14 00:00:00.000000+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '0004_oauth_clients'
down_revision: Union[str, None] = '0003_audit_log_durability'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'oauth_clients',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), nullable=False),
        sa.Column('client_id', sa.String(length=64), nullable=False),
        sa.Column('client_name', sa.String(length=255), nullable=False),
        sa.Column('application_type', sa.String(length=20), nullable=False),
        sa.Column('redirect_uris', sa.ARRAY(sa.String()), nullable=False),
        sa.Column('grant_types', sa.ARRAY(sa.String()), nullable=False),
        sa.Column('response_types', sa.ARRAY(sa.String()), nullable=False),
        sa.Column('token_endpoint_auth_method', sa.String(length=20), nullable=False),
        sa.Column('raw_metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_oauth_clients_org_id'), 'oauth_clients', ['org_id'], unique=False)
    op.create_index(op.f('ix_oauth_clients_client_id'), 'oauth_clients', ['client_id'], unique=True)


def downgrade() -> None:
    op.drop_index(op.f('ix_oauth_clients_client_id'), table_name='oauth_clients')
    op.drop_index(op.f('ix_oauth_clients_org_id'), table_name='oauth_clients')
    op.drop_table('oauth_clients')
