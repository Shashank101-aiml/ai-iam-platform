"""
JWT module for AI Agent identity tokens.

Key design decisions:
- RS256 (asymmetric): verification key can be shared publicly; only this service signs
- Short TTL (15 min): limits blast radius if a token leaks
- jti (JWT ID): every token has a unique ID for revocation tracking
- agent_id + org_id in payload: no DB lookup needed during request auth
- causal_trace_id: links tokens to the audit chain that spawned them
"""

import uuid
import time
from datetime import datetime, timezone
from typing import Optional

from jose import jwt, JWTError, ExpiredSignatureError
from jose.exceptions import JWTClaimsError

from app.core.config import settings
from app.core.constants import TokenType, PermissionScope


def _load_private_key() -> str:
    with open(settings.JWT_PRIVATE_KEY_PATH, "r") as f:
        return f.read()


def _load_public_key() -> str:
    with open(settings.JWT_PUBLIC_KEY_PATH, "r") as f:
        return f.read()


def create_agent_access_token(
    agent_id: str,
    org_id: str,
    scopes: list[PermissionScope],
    causal_trace_id: str,
    parent_agent_id: Optional[str] = None,
    delegation_depth: int = 0,
) -> dict:
    """
    Issue a short-lived access token for an AI agent.

    Returns both the token string and the jti so the caller
    can register it in the revocation index.
    """
    now = int(time.time())
    jti = str(uuid.uuid4())
    exp = now + (settings.AGENT_ACCESS_TOKEN_EXPIRE_MINUTES * 60)

    payload = {
        # Standard JWT claims
        "iss": f"https://{settings.SPIFFE_TRUST_DOMAIN}",
        "sub": f"agent:{agent_id}",
        "aud": "ai-iam-platform",
        "iat": now,
        "exp": exp,
        "jti": jti,                          # Unique ID — used for revocation

        # Custom claims
        "token_type": TokenType.ACCESS,
        "agent_id": agent_id,
        "org_id": org_id,
        "scopes": [s.value for s in scopes],
        "causal_trace_id": causal_trace_id,  # Links to audit log chain
        "delegation_depth": delegation_depth, # Enforced at validation time

        # Parent agent — present when this token was issued via delegation
        **({"parent_agent_id": parent_agent_id} if parent_agent_id else {}),
    }

    token = jwt.encode(payload, _load_private_key(), algorithm=settings.JWT_ALGORITHM)
    return {"token": token, "jti": jti, "exp": exp}


def create_delegation_token(
    delegating_agent_id: str,
    delegatee_agent_id: str,
    org_id: str,
    scopes: list[PermissionScope],
    causal_trace_id: str,
    current_depth: int,
) -> dict:
    """
    Issue a delegation token that lets one agent act on behalf of another.

    Hard-stops at MAX_DELEGATION_DEPTH to prevent infinite chains.
    The scopes here can ONLY be a subset of the delegating agent's own scopes
    — callers must enforce this before calling.
    """
    if current_depth >= settings.MAX_DELEGATION_DEPTH:
        raise ValueError(
            f"Delegation depth {current_depth} exceeds maximum "
            f"{settings.MAX_DELEGATION_DEPTH}. Possible runaway agent chain."
        )

    now = int(time.time())
    jti = str(uuid.uuid4())
    # Delegation tokens expire faster than regular access tokens
    exp = now + 600  # 10 minutes hard ceiling

    payload = {
        "iss": f"https://{settings.SPIFFE_TRUST_DOMAIN}",
        "sub": f"agent:{delegatee_agent_id}",
        "aud": "ai-iam-platform",
        "iat": now,
        "exp": exp,
        "jti": jti,
        "token_type": TokenType.DELEGATION,
        "agent_id": delegatee_agent_id,
        "delegated_by": delegating_agent_id,
        "org_id": org_id,
        "scopes": [s.value for s in scopes],
        "causal_trace_id": causal_trace_id,
        "delegation_depth": current_depth + 1,
    }

    token = jwt.encode(payload, _load_private_key(), algorithm=settings.JWT_ALGORITHM)
    return {"token": token, "jti": jti, "exp": exp}


def verify_agent_token(token: str) -> dict:
    """
    Verify and decode an agent JWT.

    Does NOT check the jti revocation list — that happens in middleware
    using the jti from the decoded payload to avoid unnecessary DB hits
    on tokens that are almost certainly valid.

    Raises:
        ExpiredSignatureError: token has expired
        JWTClaimsError: audience/issuer mismatch
        JWTError: signature invalid or malformed
    """
    try:
        payload = jwt.decode(
            token,
            _load_public_key(),
            algorithms=[settings.JWT_ALGORITHM],
            audience="ai-iam-platform",
            issuer=f"https://{settings.SPIFFE_TRUST_DOMAIN}",
        )
        return payload
    except ExpiredSignatureError:
        raise ExpiredSignatureError("Agent token has expired")
    except JWTClaimsError as e:
        raise JWTClaimsError(f"Token claims invalid: {e}")
    except JWTError as e:
        raise JWTError(f"Token verification failed: {e}")


def extract_jti(token: str) -> Optional[str]:
    """
    Extract jti without full verification.
    Used for revocation list lookup before signature check.
    """
    try:
        # decode without verification — safe here because we only extract jti
        # full verification happens right after
        unverified = jwt.get_unverified_claims(token)
        return unverified.get("jti")
    except Exception:
        return None
