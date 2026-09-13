"""
On-Behalf-Of Grant model — Slice 11's "minimal grant primitive".

Distinct from DelegationGrant (agent-to-agent scope attenuation,
Slice 5): this is an OPERATOR vouching that an agent's tokens should
carry THEIR human authority, for a bounded scope and TTL. An agent's
permanent activated_by_user_id (see models/agent.py) is the default
human anchor for its root tokens; a grant here lets an operator
override that default temporarily — e.g. "for the next 2 hours, this
agent acts as me for [read, report:generate]" — without touching who
originally activated it, and revocably (unlike activation, which is a
one-time, permanent fact about the agent's history).

Resolution order at token-mint time (see agent_service.resolve_on_behalf_of):
an active, unexpired grant whose scopes cover the request wins over the
agent's activated_by_user_id default.
"""

from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, ARRAY
from sqlalchemy.orm import relationship
from app.models.base import Base, TimestampMixin, generate_uuid


class OnBehalfOfGrant(Base, TimestampMixin):
    __tablename__ = "on_behalf_of_grants"

    id = Column(String, primary_key=True, default=generate_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False, index=True)
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False, index=True)

    # The operator vouching for this agent — becomes the on_behalf_of
    # claim's value on any token this grant covers.
    granted_by_user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)

    # Bounded, not open-ended: the agent may act as this human ONLY for
    # these scopes. A token request for a scope outside this set falls
    # back to activated_by_user_id (or None) rather than being widened.
    scopes = Column(ARRAY(String), nullable=False)

    is_active = Column(Boolean, default=True, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revocation_reason = Column(String(255), nullable=True)

    agent = relationship("Agent")

    def __repr__(self):
        return f"<OnBehalfOfGrant agent={self.agent_id} granted_by={self.granted_by_user_id}>"
