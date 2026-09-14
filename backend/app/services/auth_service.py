"""
Auth Service — for human operators managing the platform.

Agents authenticate via API keys or JWTs (handled by middleware).
This service handles human login/logout for the dashboard.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

import bcrypt
from jose import jwt
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException

from app.models.user import User
from app.core.config import settings
from app.repositories.user_repo import user_repo


class AuthService:

    async def authenticate_user(
        self,
        db: AsyncSession,
        *,
        email: str,
        password: str,
        org_id: str,
    ) -> Optional[User]:
        user = await user_repo.get_by_email_and_org(db, email, org_id)
        if not user or not user.is_active:
            return None
        if not bcrypt.checkpw(password.encode(), user.hashed_password.encode()):
            return None
        return user

    async def create_user(
        self,
        db: AsyncSession,
        *,
        email: str,
        password: str,
        org_id: str,
    ) -> User:
        existing = await user_repo.get_by_email(db, email)
        if existing:
            raise HTTPException(status_code=409, detail="Email already registered")

        salt = bcrypt.gensalt(rounds=settings.BCRYPT_ROUNDS)
        hashed = bcrypt.hashpw(password.encode(), salt).decode()

        user = User(
            id=str(uuid.uuid4()),
            org_id=org_id,
            email=email.lower().strip(),
            hashed_password=hashed,
            is_active=True,
        )
        return await user_repo.create(db, user)

    def create_access_token(self, user_id: str, org_id: str) -> str:
        """
        Issue a JWT for dashboard operators. Different from agent tokens:
        symmetric HS256 (a single shared JWT_SECRET_KEY, simpler than
        managing an RSA keypair for a token only this service issues and
        verifies) and an 8-hour, workday-length TTL rather than agent
        tokens' 15 minutes.

        That TTL is not backed by MFA or any other mitigating control —
        no MFA exists anywhere in this codebase. It's a plain trade-off
        of session convenience against exposure window if a token leaks,
        made here explicitly rather than justified by a control that
        isn't actually there.
        """
        exp = datetime.now(timezone.utc) + timedelta(hours=8)
        payload = {
            "sub": user_id,
            "org_id": org_id,
            "type": "user",
            "exp": exp,
            "jti": str(uuid.uuid4()),
        }
        return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm="HS256")


auth_service = AuthService()
