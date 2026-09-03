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


class OrganizationResponse(OrganizationBase):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: str
    is_active: bool
    created_at: datetime
    updated_at: datetime
