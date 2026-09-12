from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey, ARRAY
from sqlalchemy.orm import relationship
from app.models.base import Base, TimestampMixin, generate_uuid


class DelegationGrant(Base, TimestampMixin):
    __tablename__ = "delegation_grants"

    id = Column(String, primary_key=True, default=generate_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False, index=True)

    # The agent issuing the delegation
    delegating_agent_id = Column(String, ForeignKey("agents.id"), nullable=False, index=True)
    # The agent receiving the delegation
    delegatee_agent_id = Column(String, ForeignKey("agents.id"), nullable=False, index=True)

    # Scopes granted (always a subset of delegating agent's own scopes)
    scopes = Column(ARRAY(String), nullable=False)

    # Position in the delegation chain
    delegation_depth = Column(Integer, nullable=False)

    # Signed JWT ID that authorized this delegation
    delegation_jti = Column(String, unique=True, nullable=False)

    # Lifecycle
    is_active = Column(Boolean, default=True, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revocation_reason = Column(String(255), nullable=True)

    # Audit linkage — for correlating this grant with the audit chain and
    # other events in the same causal trace. NOT used to reconstruct the
    # delegation lineage itself: causal_trace_id can legitimately be
    # shared across unrelated branches (e.g. every token exchange that
    # doesn't specify one defaults to the same literal string), so using
    # it as a chain-identity key would risk unrelated agents appearing
    # to share a delegation ancestry. parent_grant_id below is the
    # unambiguous link for that.
    causal_trace_id = Column(String, nullable=False, index=True)

    # The grant that gave the delegating agent ITS authority for this
    # specific hop — found by matching the delegating agent's verified
    # token jti against another grant's delegation_jti at the moment of
    # delegation. None when the delegating agent is acting on its own
    # root access token (never itself a delegatee), i.e. it originates
    # this chain. Walking this pointer is how delegation_service builds
    # the real DelegationChain for depth/cycle checks — see
    # DelegationService._load_chain.
    parent_grant_id = Column(String, ForeignKey("delegation_grants.id"), nullable=True, index=True)

    # Relationships
    delegating_agent = relationship(
        "Agent", foreign_keys=[delegating_agent_id],
        back_populates="delegation_grants_given"
    )
    delegatee_agent = relationship(
        "Agent", foreign_keys=[delegatee_agent_id],
        back_populates="delegation_grants_received"
    )
    parent_grant = relationship(
        "DelegationGrant", remote_side=[id], foreign_keys=[parent_grant_id]
    )

    def __repr__(self):
        return (
            f"<DelegationGrant {self.delegating_agent_id} "
            f"→ {self.delegatee_agent_id} depth={self.delegation_depth}>"
        )
