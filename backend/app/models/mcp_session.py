"""
MCP Session model — records every tool call through the proxy.

We store HASHES of arguments and results, not the values themselves.
Reasons:
1. Args may contain secrets the agent received (API keys, passwords)
2. Results may contain sensitive data (PII, financial data)
3. Hashes let us detect replay attacks and verify integrity
   without storing the sensitive payload

The causal_trace_id links this to the agent's JWT and the audit log
entry for this same action, so you get a full picture:
  JWT (who) → audit_log (what decision) → mcp_session (what happened)
"""

from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey, Text, Index
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from app.models.base import Base, TimestampMixin, generate_uuid


class McpSession(Base, TimestampMixin):
    __tablename__ = "mcp_sessions"

    id = Column(String, primary_key=True, default=generate_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False, index=True)
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False, index=True)

    # MCP server details
    mcp_server_id = Column(String, nullable=False, index=True)
    mcp_server_url = Column(String(512), nullable=False)
    tool_name = Column(String(255), nullable=False, index=True)

    # Content hashes — never raw args/results
    args_hash = Column(String(64), nullable=True)    # SHA256(JSON(args))
    result_hash = Column(String(64), nullable=True)  # SHA256(JSON(result))
    # Safe-to-store metadata about the call (no sensitive values)
    args_metadata = Column(JSONB, nullable=True)     # e.g. {"arg_count": 3, "has_file": true}

    # Outcome
    status = Column(String(50), nullable=False)   # "success", "error", "blocked"
    error_code = Column(String(100), nullable=True)
    duration_ms = Column(Integer, nullable=True)  # How long did the tool take?

    # Was this call allowed or blocked by policy?
    policy_decision = Column(String(50), nullable=False)  # "allowed", "blocked"
    blocking_reason = Column(String(255), nullable=True)

    # Provenance tainting (Slice 13): did THIS call's result come from a
    # source the platform doesn't control (web search, an external MCP
    # server, arbitrary file content) — per the calling agent's own
    # mcp_bindings[].untrusted_source, operator-authored like tool_filter,
    # never agent-supplied. Only ever True on a "success" row; a blocked
    # or errored call never actually retrieved content, so it can't have
    # tainted anything. mcp_proxy_service._trace_is_tainted walks prior
    # rows sharing a causal_trace_id to decide whether a LATER call in
    # the same trace should be treated as tainted too — the taint
    # propagates forward through the trace, it isn't recomputed here.
    source_untrusted = Column(Boolean, nullable=False, default=False)

    # Causal linkage
    causal_trace_id = Column(String, nullable=False, index=True)
    audit_log_id = Column(String, ForeignKey("audit_logs.id"), nullable=True)

    __table_args__ = (
        # Every org-scoped listing query (mcp_session_repo.get_by_agent,
        # api/mcp_proxy.py's list_mcp_sessions) filters on org_id and
        # orders by created_at — a plain ascending composite index lets
        # Postgres satisfy the DESC order with a backward index scan
        # instead of a sort.
        Index("ix_mcp_sessions_org_id_created_at", "org_id", "created_at"),
    )

    def __repr__(self):
        return (
            f"<McpSession agent={self.agent_id} tool={self.tool_name} "
            f"status={self.status}>"
        )
