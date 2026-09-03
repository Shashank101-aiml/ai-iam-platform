"""
Audit Log model — tamper-evident, append-only.

This is the most security-critical model. Design properties:

1. APPEND-ONLY: The DB user running the app has INSERT privilege only
   on this table — no UPDATE, no DELETE. Enforced at the Postgres role level.

2. HASH CHAIN: Each entry stores SHA256(content + previous_entry_hash).
   Mutating any entry breaks the chain. Chain can be verified at any time
   by replaying it from genesis.

3. CAUSAL TRACE: causal_trace_id links a group of audit events that
   belong to the same logical operation (e.g., one agent task run).
   parent_event_id links to the specific event that CAUSED this one.
   Together these reconstruct the full causal tree:
   
   [AGENT_ACTIVATED]  (causal_trace_id: T1)
       └── [CREDENTIAL_ISSUED]  (causal_trace_id: T1, parent: above)
               └── [MCP_TOOL_CALLED]  (causal_trace_id: T1, parent: above)

4. SEQUENCE NUMBER: Global monotonic counter per org for ordering audit
   events within the hash chain.
"""

from sqlalchemy import (
    Column, String, Integer, ForeignKey, Text, Index, CheckConstraint
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from app.models.base import Base, TimestampMixin, generate_uuid
from app.core.constants import AuditAction


class AuditLog(Base, TimestampMixin):
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, default=generate_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False, index=True)
    agent_id = Column(String, ForeignKey("agents.id"), nullable=True, index=True)

    # What happened
    action = Column(String(100), nullable=False, index=True)
    # Action details — stored as JSONB for structured querying
    # e.g. {"tool": "search_web", "args_hash": "sha256:...", "result": "success"}
    details = Column(JSONB, nullable=True)

    # Who/what performed the action
    actor_type = Column(String(50), nullable=False)  # "agent", "user", "system"
    actor_id = Column(String, nullable=False)

    # Access decision context
    resource_type = Column(String(100), nullable=True)
    resource_id = Column(String, nullable=True)
    outcome = Column(String(50), nullable=False)  # "success", "failure", "denied"

    # Causal chain linkage — the key to reconstructing what caused what
    causal_trace_id = Column(String, nullable=False, index=True)
    # ID of the audit event that directly caused this one
    parent_event_id = Column(String, ForeignKey("audit_logs.id"), nullable=True)

    # Hash chain for tamper detection
    # SHA256(action + details_json + actor_id + causal_trace_id + prev_hash)
    entry_hash = Column(String(64), nullable=False, unique=True)
    previous_hash = Column(String(64), nullable=False)  # Genesis = "0" * 64
    sequence_number = Column(Integer, nullable=False)   # Per-org monotonic counter

    # Network context
    source_ip = Column(String(45), nullable=True)   # IPv4 or IPv6
    user_agent = Column(String(255), nullable=True)

    # Relationships
    agent = relationship("Agent", back_populates="audit_logs")
    parent_event = relationship("AuditLog", remote_side=[id], foreign_keys=[parent_event_id])

    __table_args__ = (
        # Enforce uniqueness of sequence per org
        Index("ix_audit_logs_org_seq", "org_id", "sequence_number", unique=True),
        # Fast lookup for causal chain reconstruction
        Index("ix_audit_logs_causal", "causal_trace_id", "created_at"),
    )

    def __repr__(self):
        return (
            f"<AuditLog id={self.id} action={self.action} "
            f"trace={self.causal_trace_id} seq={self.sequence_number}>"
        )
