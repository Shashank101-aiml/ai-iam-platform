"""
Permission ORM model.
Represents granular, fine-grained access control scopes and resource definitions
used alongside Open Policy Agent (OPA) for relationship-based access control (ReBAC).
"""

from sqlalchemy import Column, String, Boolean, ForeignKey
from app.models.base import Base, TimestampMixin, generate_uuid


class Permission(Base, TimestampMixin):
    __tablename__ = "permissions"

    id = Column(String, primary_key=True, default=generate_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False, index=True)

    # Permission definition
    name = Column(String(100), nullable=False, index=True)
    description = Column(String(255), nullable=True)
    resource_type = Column(String(100), nullable=False, index=True)
    action = Column(String(100), nullable=False, index=True)

    # Lifecycle
    is_active = Column(Boolean, default=True, nullable=False)

    def __repr__(self):
        return f"<Permission id={self.id} {self.resource_type}:{self.action}>"
