"""audit log durability: drop hard FK on agent_id, add least-privilege audit-writer role

Revision ID: 0003_audit_log_durability
Revises: 0002_delegation_parent_grant
Create Date: 2026-09-13 00:00:00.000000+00:00

"""
import os
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0003_audit_log_durability'
down_revision: Union[str, None] = '0002_delegation_parent_grant'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

AUDIT_ROLE = "aiiam_audit_writer"


def upgrade() -> None:
    # audit_logs.agent_id must never have a hard FK to agents.id — see
    # app/models/audit_log.py for the full rationale. Auditing an action
    # BEFORE the row it describes exists (the deliberate design in
    # agent_service.register, so the audit entry survives even if the
    # write that follows fails) is a real ForeignKeyViolationError under
    # this constraint, confirmed live on every agent registration.
    op.drop_constraint('audit_logs_agent_id_fkey', 'audit_logs', type_='foreignkey')

    # Least-privilege role the audit writer actually connects as (see
    # app/db/session.py's audit_engine) — INSERT + SELECT on audit_logs
    # ONLY. No UPDATE, no DELETE, no access to any other table. This is
    # what makes "append-only" a database-enforced guarantee instead of
    # a docstring: even a fully compromised app DB role can't reach this
    # role's ability to tamper with or erase an existing entry, because
    # that ability doesn't exist for this role at all.
    password = os.environ.get("AUDIT_DB_PASSWORD", "audit_writer_dev_password").replace("'", "''")
    conn = op.get_bind()

    conn.execute(sa.text(f"""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{AUDIT_ROLE}') THEN
                CREATE ROLE {AUDIT_ROLE} LOGIN PASSWORD '{password}';
            ELSE
                ALTER ROLE {AUDIT_ROLE} LOGIN PASSWORD '{password}';
            END IF;
        END
        $$;
    """))

    db_name = conn.execute(sa.text("SELECT current_database()")).scalar()
    conn.execute(sa.text(f'GRANT CONNECT ON DATABASE "{db_name}" TO {AUDIT_ROLE}'))
    conn.execute(sa.text(f"GRANT USAGE ON SCHEMA public TO {AUDIT_ROLE}"))
    conn.execute(sa.text(f"GRANT INSERT, SELECT ON audit_logs TO {AUDIT_ROLE}"))
    # Redundant given the GRANT above never included them — stated
    # explicitly so the guarantee doesn't silently depend on nobody ever
    # running a later `GRANT ALL` out of habit.
    conn.execute(sa.text(f"REVOKE UPDATE, DELETE ON audit_logs FROM {AUDIT_ROLE}"))


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(sa.text(f"REVOKE ALL ON audit_logs FROM {AUDIT_ROLE}"))
    conn.execute(sa.text(f"REVOKE USAGE ON SCHEMA public FROM {AUDIT_ROLE}"))
    db_name = conn.execute(sa.text("SELECT current_database()")).scalar()
    conn.execute(sa.text(f'REVOKE CONNECT ON DATABASE "{db_name}" FROM {AUDIT_ROLE}'))
    conn.execute(sa.text(f"DROP ROLE IF EXISTS {AUDIT_ROLE}"))
    op.create_foreign_key('audit_logs_agent_id_fkey', 'audit_logs', 'agents', ['agent_id'], ['id'])
