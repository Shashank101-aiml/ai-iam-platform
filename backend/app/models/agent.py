"""
Agent model — the core identity primitive of this platform.

Key fields:
- spiffe_id: cryptographic workload identity (SPIFFE URI)
- parent_agent_id: enables agent hierarchy / delegation chains
- is_ephemeral: ephemeral agents exist for a single task run and
  are auto-decommissioned after completion. Static API key agents
  persist indefinitely.
- max_delegation_depth: per-agent limit (org default in config)
- allowed_scopes: what this agent is PERMITTED to request in a token
  (even if OPA would allow more — defense in depth)
"""

from sqlalchemy import (
    Column, String, Boolean, Integer, ForeignKey,
    DateTime, Text, ARRAY
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from app.models.base import Base, TimestampMixin, generate_uuid
from app.core.constants import AgentStatus


class Agent(Base, TimestampMixin):
    __tablename__ = "agents"

    id = Column(String, primary_key=True, default=generate_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False, index=True)

    # Identity
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(50), default=AgentStatus.PENDING, nullable=False, index=True)

    # SPIFFE workload identity — set after agent is activated by SPIRE
    spiffe_id = Column(String(512), unique=True, nullable=True, index=True)
    # Example: spiffe://ai-iam.internal/ns/acme/sa/agt_uuid

    # Hierarchy — for multi-agent orchestration
    parent_agent_id = Column(
        String, ForeignKey("agents.id"), nullable=True, index=True
    )
    # How deep into a delegation chain can this agent be a delegatee?
    max_delegation_depth = Column(Integer, default=3, nullable=False)

    # Ephemeral agents auto-decommission after task completion
    is_ephemeral = Column(Boolean, default=False, nullable=False)
    decommission_at = Column(DateTime(timezone=True), nullable=True)

    # Allowed scopes — intersection with token request determines actual scopes
    # Stored as PostgreSQL array for indexed lookup
    allowed_scopes = Column(ARRAY(String), nullable=False, default=list)

    # MCP server bindings — which MCP servers this agent can connect to.
    # Operator-authored (set via the agent create/update routes, never by
    # the agent itself), which is what makes server_url here trustworthy:
    # mcp_proxy_service resolves the real MCP server URL from THIS field
    # by server_id rather than accepting a URL in the tool-call request
    # body, so a compromised or malicious agent can't redirect the proxy's
    # outbound call to an arbitrary address (SSRF).
    # [{"server_id": "...", "server_url": "https://...", "tool_filter": ["search_web", "read_file"]}]
    # tool_filter is optional; omitting it allows any tool on that server.
    mcp_bindings = Column(JSONB, nullable=True, default=list)

    # Relationships
    organization = relationship("Organization", back_populates="agents")
    parent_agent = relationship("Agent", remote_side=[id], foreign_keys=[parent_agent_id])
    api_keys = relationship("ApiKey", back_populates="agent", lazy="select")
    delegation_grants_given = relationship(
        "DelegationGrant",
        foreign_keys="DelegationGrant.delegating_agent_id",
        back_populates="delegating_agent",
    )
    delegation_grants_received = relationship(
        "DelegationGrant",
        foreign_keys="DelegationGrant.delegatee_agent_id",
        back_populates="delegatee_agent",
    )

    def __repr__(self):
        return f"<Agent id={self.id} name={self.name} status={self.status}>"
