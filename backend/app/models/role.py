from sqlalchemy import Column, String, ForeignKey, Table, ARRAY
from sqlalchemy.orm import relationship
from app.models.base import Base, TimestampMixin, generate_uuid

# Many-to-many: agents can have multiple roles
agent_roles = Table(
    "agent_roles",
    Base.metadata,
    Column("agent_id", String, ForeignKey("agents.id"), primary_key=True),
    Column("role_id", String, ForeignKey("roles.id"), primary_key=True),
)


class Role(Base, TimestampMixin):
    __tablename__ = "roles"

    id = Column(String, primary_key=True, default=generate_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    description = Column(String(255), nullable=True)
    # Scopes this role grants
    scopes = Column(ARRAY(String), nullable=False, default=list)

    def __repr__(self):
        return f"<Role id={self.id} name={self.name}>"
