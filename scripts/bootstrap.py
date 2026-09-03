"""
Production Bootstrap Script for AI-IAM Platform.

Creates exactly one Organization and one superuser operator account —
nothing else. This is the out-of-band path that breaks the platform's
chicken-and-egg problem: every operator-facing route requires an
authenticated User, and POST /api/v1/organizations requires a superuser,
so the very first org and the very first operator can't come from the
HTTP API at all. Run this once, from a shell with access to the
database (a `docker exec` into the running container, or a one-off
`docker compose run`), before anyone can log in.

This assumes migrations have already been applied (`alembic upgrade
head`) — it does NOT call init_db()/create_all like scripts/seed_db.py
does. A production deployment's schema should only ever come from
Alembic; silently creating tables here would desync alembic_version
from what's actually running, exactly the kind of drift Slice 2 fixed.

For local development, use scripts/seed_db.py instead — it calls the
bootstrap_organization() function below for the org + admin account,
then layers demo agents/roles/permissions on top. This script has no
demo data of its own; it is meant to be safe to run against a real
deployment.

Usage:
    python scripts/bootstrap.py --org-name "Acme Corp" --admin-email admin@acme.com

    Password resolution order:
      1. --admin-password flag (visible in shell history — avoid in shared/prod shells)
      2. AIIAM_BOOTSTRAP_PASSWORD environment variable
      3. Auto-generated and printed once (recommended for real deployments)
"""

import argparse
import asyncio
import re
import secrets
import sys
import uuid
from typing import Optional, Tuple

import bcrypt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import AsyncSessionLocal
from app.models.organization import Organization
from app.models.user import User
from app.core.config import settings

MIN_PASSWORD_LENGTH = 12


class BootstrapConflict(Exception):
    """Raised when the requested org slug or admin email is already in use."""


def slugify(name: str) -> str:
    slug = name.lower().strip()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"[\s_-]+", "-", slug)
    return slug.strip("-")


async def bootstrap_organization(
    db: AsyncSession,
    *,
    org_name: str,
    org_slug: str,
    admin_email: str,
    admin_password: str,
    is_superuser: bool = False,
) -> Tuple[Organization, User]:
    """
    Create one Organization and one admin User inside the given
    session. Caller is responsible for commit().

    is_superuser defaults to False deliberately: is_superuser now also
    controls cross-org visibility (api/organizations.py — GET on another
    org's record, or the full org list, both require it), not just
    "full control of your own org" — every operator already gets that
    regardless of the flag. If this script is run once per tenant to
    onboard separate customer orgs, defaulting to True would hand every
    new tenant's admin visibility into every OTHER tenant. Pass
    is_superuser=True only for a genuine platform operator — most
    commonly the very first account on a fresh deployment, who then
    needs to create further organizations via POST /organizations.

    Raises BootstrapConflict if the org slug or admin email already
    exists — org slugs are scoped globally in this schema (no
    per-tenant namespacing), and email is a global unique column on
    User, so both checks matter independently.
    """
    existing_org = await db.execute(
        select(Organization).where(Organization.slug == org_slug)
    )
    if existing_org.scalar_one_or_none():
        raise BootstrapConflict(f"Organization with slug '{org_slug}' already exists")

    existing_user = await db.execute(select(User).where(User.email == admin_email))
    if existing_user.scalar_one_or_none():
        raise BootstrapConflict(f"User with email '{admin_email}' already exists")

    org = Organization(
        id=str(uuid.uuid4()),
        name=org_name,
        slug=org_slug,
        is_active=True,
    )
    db.add(org)
    await db.flush()

    salt = bcrypt.gensalt(rounds=settings.BCRYPT_ROUNDS)
    hashed = bcrypt.hashpw(admin_password.encode(), salt).decode()
    admin_user = User(
        id=str(uuid.uuid4()),
        org_id=org.id,
        email=admin_email,
        hashed_password=hashed,
        is_active=True,
        is_superuser=is_superuser,
    )
    db.add(admin_user)
    await db.flush()

    return org, admin_user


def _resolve_password(cli_password: Optional[str]) -> Tuple[str, bool]:
    """Returns (password, was_generated)."""
    import os

    if cli_password:
        password = cli_password
    elif os.environ.get("AIIAM_BOOTSTRAP_PASSWORD"):
        password = os.environ["AIIAM_BOOTSTRAP_PASSWORD"]
    else:
        return secrets.token_urlsafe(18), True

    if len(password) < MIN_PASSWORD_LENGTH:
        print(
            f"Error: password must be at least {MIN_PASSWORD_LENGTH} characters.",
            file=sys.stderr,
        )
        sys.exit(1)
    return password, False


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Bootstrap a new organization and its first operator."
    )
    parser.add_argument("--org-name", required=True, help="Display name, e.g. 'Acme Corp'")
    parser.add_argument(
        "--org-slug",
        default=None,
        help="URL-safe org identifier; derived from --org-name if omitted",
    )
    parser.add_argument("--admin-email", required=True)
    parser.add_argument(
        "--admin-password",
        default=None,
        help="Avoid in shared shells — prefer AIIAM_BOOTSTRAP_PASSWORD or omit to auto-generate",
    )
    parser.add_argument(
        "--superuser",
        action="store_true",
        help=(
            "Grant platform-wide superuser (visibility into every org, not just this "
            "one — see bootstrap_organization()'s docstring). Use only for a genuine "
            "platform operator, most commonly the very first account on a fresh "
            "deployment. Omit when onboarding a new tenant's own admin."
        ),
    )
    args = parser.parse_args()

    org_slug = args.org_slug or slugify(args.org_name)
    admin_password, was_generated = _resolve_password(args.admin_password)

    async with AsyncSessionLocal() as db:
        try:
            org, admin_user = await bootstrap_organization(
                db,
                org_name=args.org_name,
                org_slug=org_slug,
                admin_email=args.admin_email,
                admin_password=admin_password,
                is_superuser=args.superuser,
            )
        except BootstrapConflict as e:
            await db.rollback()
            print(f"Bootstrap skipped: {e}", file=sys.stderr)
            print("If this is expected, log in with the existing account instead.", file=sys.stderr)
            sys.exit(1)

        await db.commit()

    print("\nBootstrap complete.")
    print(f"   Organization: {org.name} (slug: {org.slug}, id: {org.id})")
    print(f"   Operator:     {admin_user.email} ({'superuser' if admin_user.is_superuser else 'org admin'})")
    if was_generated:
        print(f"   Password:     {admin_password}")
        print("\n   This password is shown once and is not recoverable. Store it now —")
        print("   e.g. in your secret manager — then log in and consider rotating it.")
    else:
        print("   Password:     (as provided — not re-printed)")


if __name__ == "__main__":
    asyncio.run(main())
