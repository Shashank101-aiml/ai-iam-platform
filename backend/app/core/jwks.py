"""
JWKS (JSON Web Key Set) — publishes the RS256 public key agent tokens
are verified with, in the format RFC 7517 / the OAuth discovery
metadata's jwks_uri expects, so a standard OAuth/OIDC client library
can verify a token's signature without out-of-band PEM distribution.

Never touches the private key — only core/jwt.py's _load_private_key
does that, and only to sign.
"""

import base64
import hashlib
from functools import lru_cache

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from app.core.config import settings


def _b64url_uint(value: int) -> str:
    """Base64url-encode a big-endian unsigned integer, no padding — the JWK n/e encoding RFC 7518 §6.3 specifies."""
    length = (value.bit_length() + 7) // 8
    raw = value.to_bytes(length, byteorder="big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@lru_cache()
def get_jwks() -> dict:
    """
    Build the JWKS document once and cache it — the keypair is static
    for the process lifetime (see core/jwt.py's _load_public_key: read
    from a file that isn't expected to change without a restart).
    """
    with open(settings.JWT_PUBLIC_KEY_PATH, "rb") as f:
        pem_bytes = f.read()

    public_key = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(public_key, RSAPublicKey):
        raise TypeError(
            f"JWT_PUBLIC_KEY_PATH does not hold an RSA key (got {type(public_key).__name__}) "
            f"— RS256 requires RSA."
        )
    numbers = public_key.public_numbers()

    # Stable, deterministic kid derived from the key material itself —
    # not a random value that would need persisting somewhere and
    # would silently go stale on a restart if it weren't recomputed
    # from the same source every time.
    kid = hashlib.sha256(pem_bytes).hexdigest()[:16]

    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": settings.JWT_ALGORITHM,
                "kid": kid,
                "n": _b64url_uint(numbers.n),
                "e": _b64url_uint(numbers.e),
            }
        ]
    }
