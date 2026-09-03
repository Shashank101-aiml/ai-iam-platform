from sqlalchemy import Column, String, Boolean, Text
from sqlalchemy.orm import relationship
from app.models.base import Base, TimestampMixin, generate_uuid


class Organization(Base, TimestampMixin):
    __tablename__ = "organizations"

    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    is_active = Column(Boolean, default=True, nullable=False)
    metadata_ = Column("metadata", Text, nullable=True)  # JSON blob

    # Relationships
    agents = relationship("Agent", back_populates="organization", lazy="select")
    users = relationship("User", back_populates="organization", lazy="select")

    def __repr__(self):
        return f"<Organization id={self.id} slug={self.slug}>"
