"""
Operator Authentication Router.
Facilitates human login and session management for the dashboard interface.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas.user import UserCreate, UserLogin, UserResponse, TokenPayload
from app.services.auth_service import auth_service
from app.api.deps import get_current_user
from app.models.user import User

router = APIRouter()


@router.post("/login", response_model=TokenPayload)
async def login(credentials: UserLogin, db: AsyncSession = Depends(get_db)):
    """
    Authenticate human operator with email and password, returning an HS256 JWT.
    Note: Org lookup defaults to the user's registered organization.
    """
    from app.repositories.user_repo import user_repo
    user = await user_repo.get_by_email(db, credentials.email)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    authenticated = await auth_service.authenticate_user(
        db,
        email=credentials.email,
        password=credentials.password,
        org_id=user.org_id,
    )
    if not authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    token = auth_service.create_access_token(user.id, user.org_id)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": 28800,  # 8 hours
    }


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_in: UserCreate, db: AsyncSession = Depends(get_db)):
    """Register a new human operator under an existing organization."""
    user = await auth_service.create_user(
        db,
        email=user_in.email,
        password=user_in.password,
        org_id=user_in.org_id,
    )
    await db.commit()
    await db.refresh(user)
    return user


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    """Return profile of the currently logged in human operator."""
    return current_user
