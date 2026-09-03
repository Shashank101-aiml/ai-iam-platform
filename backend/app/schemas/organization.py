"""
Organization Pydantic v2 schemas.
"""

from typing import Optional
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class OrganizationBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    slug: str = Field(..., min_length=2, max_length=100)
    metadata_: Optional[str] = Field(None, alias="metadata")


class OrganizationCreate(OrganizationBase):
    pass


class OrganizationUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=255)
    is_active: Optional[bool] = None
    metadata_: Optional[str] = Field(None, alias="metadata")


class OrganizationResponse(BaseModel):
    """
    Deliberately not a subclass of OrganizationBase: that base's
    metadata_ field aliases to "metadata" for JSON input/output, which
    is correct for request bodies (plain dicts) but wrong here. Every
    SQLAlchemy declarative model has a class-level `.metadata` attribute
    (its schema registry) — when Pydantic builds this response
    from_attributes=True off an Organization ORM instance, an alias of
    "metadata" makes it read that registry object instead of the actual
    metadata_ column value, and fail validation
    ('Input should be a valid string', got a MetaData object).
    validation_alias="metadata_" reads the real column; the JSON key
    stays "metadata" via serialization_alias for API consistency with
    OrganizationCreate/OrganizationUpdate's input shape.
    """
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: str
    name: str
    slug: str
    metadata_: Optional[str] = Field(
        None, validation_alias="metadata_", serialization_alias="metadata"
    )
    is_active: bool
    created_at: datetime
    updated_at: datetime
