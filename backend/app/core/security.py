"""
Security primitives for credential management.

Key design decisions:
- API keys are NEVER stored in plaintext — only bcrypt hash is persisted
- Keys are prefixed ("aiiam_") so they're identifiable in logs/git leaks
- Rotation issues new key BEFORE revoking old one (zero-downtime)
- PKCE flow prevents authorization code interception attacks
"""

import secrets
import hashlib
import base64
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import bcrypt

from app.core.config import settings


# ── API Key Management ────────────────────────────────────────────────────────

def generate_api_key() -> Tuple[str, str]:
    """
    Generate a new API key.

    Returns:
        (plaintext_key, hashed_key)

    The plaintext key is returned ONCE and never stored.
    Only the hash goes into the database.

    Format: aiiam_<32 random bytes as hex>
    Example: aiiam_a3f9c2e1d7b4082f6a5e3c9d1b7f4e2a...
    """
    raw = secrets.token_hex(32)
    plaintext = f"{settings.API_KEY_PREFIX}{raw}"
    hashed = _hash_api_key(plaintext)
    return plaintext, hashed


def _hash_api_key(plaintext: str) -> str:
    """
    Hash an API key with bcrypt.

    We hash API keys (not just passwords) because if the DB leaks,
    raw API keys are as dangerous as passwords.
    """
    salt = bcrypt.gensalt(rounds=settings.BCRYPT_ROUNDS)
    return bcrypt.hashpw(plaintext.encode(), salt).decode()


def verify_api_key(plaintext: str, hashed: str) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    try:
        return bcrypt.checkpw(plaintext.encode(), hashed.encode())
    except Exception:
        return False


def generate_key_id() -> str:
    """
    Generate a short, safe-to-log key identifier.

    This is stored in plaintext and used in audit logs so we can
    reference "which key was used" without exposing the key itself.
    """
    return f"kid_{secrets.token_hex(8)}"


# ── PKCE (Proof Key for Code Exchange) ───────────────────────────────────────
# Prevents auth code interception in agent-to-agent OAuth flows

def generate_pkce_pair() -> Tuple[str, str]:
    """
    Generate a PKCE code_verifier and code_challenge pair.

    Returns:
        (code_verifier, code_challenge)

    The agent sends code_challenge with the auth request.
    It sends code_verifier when exchanging the code for a token.
    We verify: SHA256(code_verifier) == code_challenge
    """
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    code_challenge = _s256_challenge(code_verifier)
    return code_verifier, code_challenge


def _s256_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def verify_pkce_challenge(code_verifier: str, stored_challenge: str) -> bool:
    """Verify a PKCE exchange. Constant-time safe."""
    expected = _s256_challenge(code_verifier)
    return secrets.compare_digest(expected, stored_challenge)


# ── Credential Rotation ───────────────────────────────────────────────────────

def should_rotate_key(created_at: datetime, ttl_days: int) -> bool:
    """
    Check if a key is within the rotation window (last 20% of TTL).

    Proactive rotation: keys are rotated BEFORE they expire,
    not after. This avoids the "expired key breaks production" scenario.
    """
    now = datetime.now(timezone.utc)
    age = (now - created_at).total_seconds()
    ttl_seconds = ttl_days * 86400
    rotation_window = ttl_seconds * 0.2  # last 20% of TTL = rotation time
    return age >= (ttl_seconds - rotation_window)


def is_key_expired(expires_at: Optional[datetime]) -> bool:
    if expires_at is None:
        return False
    return datetime.now(timezone.utc) > expires_at


# ── Audit Hash Chain ──────────────────────────────────────────────────────────

def compute_entry_hash(content: str, previous_hash: str) -> str:
    """
    Compute an audit log entry hash for tamper-evident chaining.

    Each entry hashes its own content + the previous entry's hash.
    Mutating any entry breaks every subsequent hash, making tampering
    detectable by replaying the chain.
    """
    combined = f"{previous_hash}:{content}"
    return hashlib.sha256(combined.encode()).hexdigest()


AUDIT_CHAIN_GENESIS = "0" * 64  # Starting hash for the first entry
