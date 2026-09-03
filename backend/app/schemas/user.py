"""
User & Authentication Pydantic v2 schemas.
"""

from typing import Optional
from datetime import datetime
from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserCreate(BaseModel):
    org_id: str
    email: EmailStr
    password: str = Field(..., min_length=8)
    is_superuser: bool = False


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    org_id: str
    email: str
    is_active: bool
    is_superuser: bool
    created_at: datetime
    updated_at: datetime


class TokenPayload(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
