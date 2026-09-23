"""
Operator Authentication Router.
Facilitates human login and session management for the dashboard interface.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.rate_limit import rate_limit_login, rate_limit_trial_signup
from app.core.constants import AuditAction
from app.db.session import get_db
from app.schemas.user import UserCreate, UserLogin, UserResponse, TokenPayload, TrialSignupRequest
from app.services.auth_service import auth_service
from app.services.organization_service import org_service
from app.repositories.audit_repo import audit_repo
from app.api.deps import get_current_user
from app.models.user import User

router = APIRouter()


@router.post("/login", response_model=TokenPayload, dependencies=[Depends(rate_limit_login)])
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


@router.post(
    "/trial-signup",
    response_model=TokenPayload,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit_trial_signup)],
)
async def trial_signup(signup_in: TrialSignupRequest, db: AsyncSession = Depends(get_db)):
    """
    Public, unauthenticated self-serve signup: creates a brand new
    Organization and its first admin User together, then logs that
    user in immediately (same token shape as /login).

    Distinct from POST /organizations (superuser-only, creates no
    user) and POST /auth/register (needs an org_id the caller doesn't
    have yet) — neither of those can bootstrap a first account for a
    genuinely new visitor. org_service.create() and
    auth_service.create_user() are reused unchanged; create_user()
    never reads or sets is_superuser from its input, so the new admin
    is always a regular (non-superuser) operator scoped to their own
    org, same as any other tenant's admin.
    """
    org = await org_service.create(
        db,
        name=signup_in.org_name,
        actor_id="anonymous:trial-signup",
    )
    user = await auth_service.create_user(
        db,
        email=signup_in.admin_email,
        password=signup_in.admin_password,
        org_id=org.id,
    )
    await db.commit()
    await db.refresh(user)

    await audit_repo.append(
        org_id=org.id,
        action=AuditAction.ORGANIZATION_CREATED,
        actor_type="user",
        actor_id=f"user:{user.id}",
        causal_trace_id=f"trial_signup:{org.id}",
        outcome="success",
        details={"org_name": org.name, "admin_email": user.email},
    )

    token = auth_service.create_access_token(user.id, user.org_id)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": 28800,  # 8 hours, matching /login
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
