"""
Structured JSON logging (Slice 14).

Every log line becomes one JSON object with a fixed set of top-level
keys (timestamp, level, logger, message, causal_trace_id) instead of
the stdlib's default free-text interpolated line — a log aggregator can
index/query on those keys directly, and causal_trace_id lets every log
line emitted while handling one request be correlated with that same
request's audit_logs/mcp_sessions rows (see docs on
TracePropagationMiddleware) without changing a single logger.info(...)
call site to pass it explicitly.

REDACTION: this platform's own API key format (`aiiam_<64 hex chars>`,
see core/security.py) is deliberately easy to grep for in a leaked log
file — which cuts both ways. A stray f"issued key {plaintext_key}"
somewhere (instead of the safe key_hint) would make a real credential
trivially greppable too. _redact() masks any substring matching that
shape before a record is ever written, so this category of leak is
closed at the logging layer itself rather than relying on every call
site to remember not to interpolate a secret.
"""

import contextvars
import json
import logging
import re

# Populated by TracePropagationMiddleware.dispatch at the top of every
# request; read here rather than threaded through every function
# signature. Default "-" (not None) so a log line emitted outside any
# request (startup, a background worker) still serializes cleanly.
causal_trace_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "causal_trace_id", default="-"
)

# Matches this platform's own plaintext API key shape exactly (see
# core/security.py's generate_api_key: "aiiam_" + 64 hex chars) — not a
# generic secret-scanner, just the one format this codebase actually
# produces and could accidentally log.
_API_KEY_PATTERN = re.compile(r"aiiam_[0-9a-f]{16,}")


def _redact(text: str) -> str:
    def _mask(match: "re.Match[str]") -> str:
        secret = match.group(0)
        # Keep the prefix (identifies it as an aiiam key, per
        # core/security.py's own stated reason for the prefix — "so
        # they're identifiable in logs/git leaks") and the last 4 chars
        # (matches key_hint, safe to display) — mask everything between.
        return f"aiiam_***REDACTED***{secret[-4:]}"

    return _API_KEY_PATTERN.sub(_mask, text)


class TraceIdFilter(logging.Filter):
    """Attaches the current request's causal_trace_id to every record passing through."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.causal_trace_id = causal_trace_id_var.get()
        return True


class RedactingJSONFormatter(logging.Formatter):
    """One JSON object per line. Redacts plaintext API keys from the message before emission."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": _redact(record.getMessage()),
            "causal_trace_id": getattr(record, "causal_trace_id", "-"),
        }
        if record.exc_info:
            payload["exception"] = _redact(self.formatException(record.exc_info))
        return json.dumps(payload)


def configure_logging(level: int = logging.INFO, sql_echo: bool = False) -> None:
    """
    Replace the root logger's handlers with one stream handler emitting
    redacted, structured JSON. Called once at app startup, before
    anything meaningful logs — in particular, before app.db.session
    creates its engines (see that module's own comment on why echo=
    settings.DEBUG was replaced with this sql_echo flag).

    Idempotent — clears any handlers already attached before adding its
    own, so calling this more than once (app reload, a test importing
    app.main twice) never stacks duplicate handlers and never double-
    emits a line.

    sql_echo controls the "sqlalchemy.engine" logger's LEVEL directly
    (INFO to see every statement, WARNING to silence them) rather than
    SQLAlchemy's own echo=True shortcut, which self-installs a SECOND,
    plain-text handler directly onto that logger regardless of what
    root's own handlers look like — see app/db/session.py's engine
    definitions for the live-confirmed duplicate-log-line bug that
    caused. Going through the level instead means SQL statements still
    flow through this one JSON handler via ordinary propagation.
    """
    root = logging.getLogger()
    root.setLevel(level)
    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler()
    handler.addFilter(TraceIdFilter())
    handler.setFormatter(RedactingJSONFormatter())
    root.addHandler(handler)

    logging.getLogger("sqlalchemy.engine").setLevel(
        logging.INFO if sql_echo else logging.WARNING
    )
