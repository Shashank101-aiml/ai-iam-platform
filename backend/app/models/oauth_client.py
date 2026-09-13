"""
OAuth Client model — Dynamic Client Registration (RFC 7591).

Every client here is a PUBLIC client: OAuth 2.1 mandates PKCE for every
grant regardless of client type, which is what actually secures the
authorization_code exchange — a client_secret adds nothing for a
native/CLI app that can't keep it confidential anyway, so none is
issued (token_endpoint_auth_method is always "none").

Registration itself is operator-gated (Depends(get_current_user) on
POST /api/v1/oauth/register), not anonymous — RFC 7591 §3 explicitly
allows requiring an initial access token before registration, and an
anonymous registration endpoint would have no org to attribute the
client to at all in this multi-tenant platform.
"""

from sqlalchemy import Column, String, ForeignKey, ARRAY
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from app.models.base import Base, TimestampMixin, generate_uuid


class OAuthClient(Base, TimestampMixin):
    __tablename__ = "oauth_clients"

    id = Column(String, primary_key=True, default=generate_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False, index=True)

    # Public identifier — safe to embed in a client app, safe to log.
    client_id = Column(String(64), unique=True, nullable=False, index=True)

    client_name = Column(String(255), nullable=False)

    # "web" (confidential-shaped, https-only redirects) or "native"
    # (desktop/CLI — loopback http://127.0.0.1:<port>/... and
    # http://localhost:<port>/... redirects allowed per RFC 8252, the
    # OAuth 2.0 for Native Apps BCP). Determines which redirect_uris
    # are accepted at registration time — see oauth_service.py.
    application_type = Column(String(20), nullable=False, default="web")

    redirect_uris = Column(ARRAY(String), nullable=False)

    # Always "authorization_code" today — this platform issues its own
    # tokens (no client_credentials/refresh_token grant implemented
    # yet), stored as a list for forward compatibility with RFC 7591's
    # own schema rather than a bare string column.
    grant_types = Column(ARRAY(String), nullable=False, default=lambda: ["authorization_code"])
    response_types = Column(ARRAY(String), nullable=False, default=lambda: ["code"])

    # Always "none" — see module docstring. Stored explicitly (not
    # hardcoded at read time) so the DCR response and this row can
    # never silently drift apart.
    token_endpoint_auth_method = Column(String(20), nullable=False, default="none")

    # Full RFC 7591 registration metadata, as originally submitted —
    # kept verbatim for audit/debugging even though only the fields
    # above are actually consulted by the authorize/token endpoints.
    raw_metadata = Column(JSONB, nullable=True)

    organization = relationship("Organization")

    def __repr__(self):
        return f"<OAuthClient client_id={self.client_id} name={self.client_name}>"
