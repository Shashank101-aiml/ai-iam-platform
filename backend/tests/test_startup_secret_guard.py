"""
Slice 15 test: refuse to boot on the well-known default JWT_SECRET_KEY.

docker-compose.yml's local-dev convenience fallback
(`${JWT_SECRET_KEY:-default_super_secret_jwt_key_256_bit_string}`)
substitutes a well-known literal string whenever the host hasn't set
one — pydantic-settings accepts that as "provided," with no way to
tell it apart from a real secret. This is the app's own separate
runtime check that a real (non-DEBUG) deployment can't quietly start
signing every operator token with a value anyone who's read this
repository already knows.
"""

import pytest

from app.core.config import settings
from app.core.jwt import verify_jwt_secret_not_default, _KNOWN_DEFAULT_JWT_SECRETS


def test_refuses_default_secret_outside_debug(monkeypatch):
    monkeypatch.setattr(settings, "JWT_SECRET_KEY", next(iter(_KNOWN_DEFAULT_JWT_SECRETS)))
    with pytest.raises(RuntimeError, match="well-known default"):
        verify_jwt_secret_not_default(debug=False)


def test_allows_default_secret_in_debug_mode(monkeypatch):
    """Local dev (docker-compose's DEBUG=true) must keep working with no manual setup."""
    monkeypatch.setattr(settings, "JWT_SECRET_KEY", next(iter(_KNOWN_DEFAULT_JWT_SECRETS)))
    verify_jwt_secret_not_default(debug=True)  # must not raise


def test_allows_a_real_secret_outside_debug(monkeypatch):
    monkeypatch.setattr(settings, "JWT_SECRET_KEY", "a-genuinely-random-production-secret")
    verify_jwt_secret_not_default(debug=False)  # must not raise
