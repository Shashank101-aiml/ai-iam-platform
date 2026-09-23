"""
User & Authentication Pydantic v2 schemas.
"""

from datetime import datetime
from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserCreate(BaseModel):
    # No is_superuser: registering a user can never grant platform-wide
    # superuser (auth_service.create_user doesn't take one either). An
    # unknown key in the request body is ignored, not honoured.
    org_id: str
    email: EmailStr
    password: str = Field(..., min_length=8)


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class TrialSignupRequest(BaseModel):
    """Public, unauthenticated self-serve signup — creates a brand new
    Organization and its first (non-superuser) admin User together.
    See auth.py's /trial-signup route for why this needs to exist
    separately from the superuser-only POST /organizations."""
    org_name: str = Field(..., min_length=2, max_length=255)
    admin_email: EmailStr
    admin_password: str = Field(..., min_length=8)


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
