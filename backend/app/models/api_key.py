"""
API Key model.

Security design:
- hashed_secret: bcrypt hash of the actual key (never store plaintext)
- key_id: short safe-to-log identifier (prefix "kid_")
- key_hint: last 4 chars of plaintext key — for user to identify it in UI
- rotated_from_id: tracks rotation lineage
- previous_hash: the old hash kept for 1 TTL window during zero-downtime rotation
"""

from sqlalchemy import Column, String, Boolean, ForeignKey, DateTime, Integer, ARRAY
from sqlalchemy.orm import relationship
from app.models.base import Base, TimestampMixin, generate_uuid
from app.core.constants import CredentialType


class ApiKey(Base, TimestampMixin):
    __tablename__ = "api_keys"

    id = Column(String, primary_key=True, default=generate_uuid)
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False, index=True)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False, index=True)

    # Safe identifier for logs — never contains the actual key
    key_id = Column(String(50), unique=True, nullable=False, index=True)

    # Cryptographic storage
    hashed_secret = Column(String(255), nullable=False)

    # Last 4 chars of the plaintext key so users can identify it in the dashboard
    # e.g. "...f4e2" — safe to store and display
    key_hint = Column(String(10), nullable=False)

    # Scopes this key is authorized for (subset of agent's allowed_scopes)
    scopes = Column(ARRAY(String), nullable=False, default=list)

    # Lifecycle
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    use_count = Column(Integer, default=0, nullable=False)

    # Rotation tracking
    rotated_at = Column(DateTime(timezone=True), nullable=True)
    rotated_from_id = Column(String, ForeignKey("api_keys.id"), nullable=True)
    # During zero-downtime rotation, accept old key for a grace period
    previous_hashed_secret = Column(String(255), nullable=True)
    previous_key_expires_at = Column(DateTime(timezone=True), nullable=True)

    credential_type = Column(
        String(50), default=CredentialType.API_KEY, nullable=False
    )

    # Relationships
    agent = relationship("Agent", back_populates="api_keys")
    rotated_from = relationship("ApiKey", remote_side=[id], foreign_keys=[rotated_from_id])

    def __repr__(self):
        return f"<ApiKey key_id={self.key_id} agent_id={self.agent_id} active={self.is_active}>"
