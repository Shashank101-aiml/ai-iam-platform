"""Initial schema creating all tables for AI-IAM Platform.

Revision ID: 0001_initial_schema
Revises: 
Create Date: 2026-07-12 14:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '0001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── Organizations ────────────────────────────────────────────────────────
    op.create_table(
        'organizations',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('slug', sa.String(length=100), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('metadata', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_organizations_id'), 'organizations', ['id'], unique=False)
    op.create_index(op.f('ix_organizations_slug'), 'organizations', ['slug'], unique=True)

    # ── Users ────────────────────────────────────────────────────────────────
    op.create_table(
        'users',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('hashed_password', sa.String(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('is_superuser', sa.Boolean(), nullable=False, default=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_id'), 'users', ['id'], unique=False)
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_org_id'), 'users', ['org_id'], unique=False)

    # ── Agents ───────────────────────────────────────────────────────────────
    op.create_table(
        'agents',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('spiffe_id', sa.String(length=512), nullable=True),
        sa.Column('parent_agent_id', sa.String(), nullable=True),
        sa.Column('max_delegation_depth', sa.Integer(), nullable=False, default=3),
        sa.Column('is_ephemeral', sa.Boolean(), nullable=False, default=False),
        sa.Column('decommission_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('allowed_scopes', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('mcp_bindings', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.ForeignKeyConstraint(['parent_agent_id'], ['agents.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_agents_id'), 'agents', ['id'], unique=False)
    op.create_index(op.f('ix_agents_org_id'), 'agents', ['org_id'], unique=False)
    op.create_index(op.f('ix_agents_spiffe_id'), 'agents', ['spiffe_id'], unique=True)
    op.create_index(op.f('ix_agents_status'), 'agents', ['status'], unique=False)

    # ── API Keys ─────────────────────────────────────────────────────────────
    op.create_table(
        'api_keys',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('agent_id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), nullable=False),
        sa.Column('key_id', sa.String(length=100), nullable=False),
        sa.Column('hashed_secret', sa.String(), nullable=False),
        sa.Column('key_hint', sa.String(length=10), nullable=False),
        sa.Column('scopes', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('use_count', sa.Integer(), nullable=False, default=0),
        sa.Column('previous_hashed_secret', sa.String(), nullable=True),
        sa.Column('previous_key_expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('rotated_from_id', sa.String(), nullable=True),
        sa.Column('rotated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('credential_type', sa.String(length=50), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], ),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.ForeignKeyConstraint(['rotated_from_id'], ['api_keys.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_api_keys_id'), 'api_keys', ['id'], unique=False)
    op.create_index(op.f('ix_api_keys_agent_id'), 'api_keys', ['agent_id'], unique=False)
    op.create_index(op.f('ix_api_keys_key_id'), 'api_keys', ['key_id'], unique=True)
    op.create_index(op.f('ix_api_keys_org_id'), 'api_keys', ['org_id'], unique=False)

    # ── Permissions ──────────────────────────────────────────────────────────
    op.create_table(
        'permissions',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('resource_type', sa.String(length=100), nullable=False),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_permissions_id'), 'permissions', ['id'], unique=False)
    op.create_index(op.f('ix_permissions_org_id'), 'permissions', ['org_id'], unique=False)
    op.create_index(op.f('ix_permissions_name'), 'permissions', ['name'], unique=False)
    op.create_index(op.f('ix_permissions_resource_type'), 'permissions', ['resource_type'], unique=False)
    op.create_index(op.f('ix_permissions_action'), 'permissions', ['action'], unique=False)

    # ── Roles & Agent Roles ──────────────────────────────────────────────────
    op.create_table(
        'roles',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('scopes', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_roles_id'), 'roles', ['id'], unique=False)
    op.create_index(op.f('ix_roles_org_id'), 'roles', ['org_id'], unique=False)
    op.create_index(op.f('ix_roles_name'), 'roles', ['name'], unique=False)

    op.create_table(
        'agent_roles',
        sa.Column('agent_id', sa.String(), nullable=False),
        sa.Column('role_id', sa.String(), nullable=False),
        sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['role_id'], ['roles.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('agent_id', 'role_id')
    )

    # ── Delegation Grants ────────────────────────────────────────────────────
    op.create_table(
        'delegation_grants',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), nullable=False),
        sa.Column('delegating_agent_id', sa.String(), nullable=False),
        sa.Column('delegatee_agent_id', sa.String(), nullable=False),
        sa.Column('scopes', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('delegation_depth', sa.Integer(), nullable=False),
        sa.Column('delegation_jti', sa.String(length=100), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revocation_reason', sa.String(), nullable=True),
        sa.Column('causal_trace_id', sa.String(length=100), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['delegating_agent_id'], ['agents.id'], ),
        sa.ForeignKeyConstraint(['delegatee_agent_id'], ['agents.id'], ),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_delegation_grants_id'), 'delegation_grants', ['id'], unique=False)
    op.create_index(op.f('ix_delegation_grants_org_id'), 'delegation_grants', ['org_id'], unique=False)
    op.create_index(op.f('ix_delegation_grants_delegating_agent_id'), 'delegation_grants', ['delegating_agent_id'], unique=False)
    op.create_index(op.f('ix_delegation_grants_delegatee_agent_id'), 'delegation_grants', ['delegatee_agent_id'], unique=False)
    op.create_index(op.f('ix_delegation_grants_delegation_jti'), 'delegation_grants', ['delegation_jti'], unique=True)

    # ── Audit Logs ───────────────────────────────────────────────────────────
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), nullable=False),
        sa.Column('agent_id', sa.String(), nullable=True),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('details', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('actor_type', sa.String(length=50), nullable=False),
        sa.Column('actor_id', sa.String(), nullable=False),
        sa.Column('resource_type', sa.String(length=100), nullable=True),
        sa.Column('resource_id', sa.String(), nullable=True),
        sa.Column('outcome', sa.String(length=50), nullable=False),
        sa.Column('causal_trace_id', sa.String(length=100), nullable=False),
        sa.Column('parent_event_id', sa.String(), nullable=True),
        sa.Column('entry_hash', sa.String(length=64), nullable=False),
        sa.Column('previous_hash', sa.String(length=64), nullable=False),
        sa.Column('sequence_number', sa.Integer(), nullable=False),
        sa.Column('source_ip', sa.String(length=50), nullable=True),
        sa.Column('user_agent', sa.String(length=512), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], ),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.ForeignKeyConstraint(['parent_event_id'], ['audit_logs.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_logs_id'), 'audit_logs', ['id'], unique=False)
    op.create_index(op.f('ix_audit_logs_org_id'), 'audit_logs', ['org_id'], unique=False)
    op.create_index(op.f('ix_audit_logs_agent_id'), 'audit_logs', ['agent_id'], unique=False)
    op.create_index(op.f('ix_audit_logs_action'), 'audit_logs', ['action'], unique=False)
    op.create_index(op.f('ix_audit_logs_causal_trace_id'), 'audit_logs', ['causal_trace_id'], unique=False)
    op.create_index(op.f('ix_audit_logs_sequence_number'), 'audit_logs', ['sequence_number'], unique=False)

    # ── MCP Sessions ─────────────────────────────────────────────────────────
    op.create_table(
        'mcp_sessions',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), nullable=False),
        sa.Column('agent_id', sa.String(), nullable=False),
        sa.Column('mcp_server_id', sa.String(length=100), nullable=False),
        sa.Column('mcp_server_url', sa.String(length=512), nullable=False),
        sa.Column('tool_name', sa.String(length=100), nullable=False),
        sa.Column('args_hash', sa.String(length=64), nullable=True),
        sa.Column('result_hash', sa.String(length=64), nullable=True),
        sa.Column('args_metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('error_code', sa.String(length=100), nullable=True),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('policy_decision', sa.String(length=50), nullable=False),
        sa.Column('blocking_reason', sa.String(length=512), nullable=True),
        sa.Column('causal_trace_id', sa.String(length=100), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], ),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_mcp_sessions_id'), 'mcp_sessions', ['id'], unique=False)
    op.create_index(op.f('ix_mcp_sessions_org_id'), 'mcp_sessions', ['org_id'], unique=False)
    op.create_index(op.f('ix_mcp_sessions_agent_id'), 'mcp_sessions', ['agent_id'], unique=False)
    op.create_index(op.f('ix_mcp_sessions_mcp_server_id'), 'mcp_sessions', ['mcp_server_id'], unique=False)
    op.create_index(op.f('ix_mcp_sessions_tool_name'), 'mcp_sessions', ['tool_name'], unique=False)
    op.create_index(op.f('ix_mcp_sessions_causal_trace_id'), 'mcp_sessions', ['causal_trace_id'], unique=False)


def downgrade() -> None:
    op.drop_table('mcp_sessions')
    op.drop_table('audit_logs')
    op.drop_table('delegation_grants')
    op.drop_table('agent_roles')
    op.drop_table('roles')
    op.drop_table('permissions')
    op.drop_table('api_keys')
    op.drop_table('agents')
    op.drop_table('users')
    op.drop_table('organizations')
