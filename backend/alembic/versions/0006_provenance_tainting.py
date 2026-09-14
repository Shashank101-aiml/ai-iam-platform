"""provenance-aware authorization: taint tracking on mcp_sessions (Slice 13)

Revision ID: 0006_provenance_tainting
Revises: 0005_on_behalf_of
Create Date: 2026-09-14 00:00:00.000000+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '0006_provenance_tainting'
down_revision: Union[str, None] = '0005_on_behalf_of'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # server_default here is only to backfill existing rows under a
    # NOT NULL constraint — every row that predates this migration
    # necessarily predates provenance tracking too, so "untrusted: no"
    # is the only honest default for it. Dropped immediately after so
    # the model's own Python-side default (False) is what governs new
    # rows going forward, same pattern as every other boolean column in
    # this schema.
    op.add_column(
        'mcp_sessions',
        sa.Column('source_untrusted', sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.alter_column('mcp_sessions', 'source_untrusted', server_default=None)


def downgrade() -> None:
    op.drop_column('mcp_sessions', 'source_untrusted')
