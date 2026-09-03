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
from fastapi import HTTPException, status

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
        Issue a short-lived JWT for dashboard operators.
        Different from agent tokens — uses HS256 for simplicity,
        longer TTL since humans have MFA.
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
