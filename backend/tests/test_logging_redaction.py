"""
Slice 14 test: structured logging + redaction.

A plaintext aiiam_<hex> API key must never survive into the JSON log
output, even when a call site is careless and interpolates the full
plaintext value straight into a log message (exactly the category of
bug core/logging_config.py's redaction exists to catch — nothing in
Python stops a future contributor from writing exactly this instead of
the safe key_hint).
"""

import io
import json
import logging

from app.core.logging_config import RedactingJSONFormatter, TraceIdFilter, causal_trace_id_var


def test_plaintext_api_key_is_redacted_from_log_output():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(TraceIdFilter())
    handler.setFormatter(RedactingJSONFormatter())

    logger = logging.getLogger("test.redaction")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    logger.propagate = False

    token = causal_trace_id_var.set("trace-redaction-test")
    try:
        # This platform's real key shape (core/security.py): "aiiam_" + 64 hex chars.
        plaintext_key = "aiiam_" + "a1b2c3d4" * 8
        logger.info(f"issued key {plaintext_key} to agent agt-123")
    finally:
        causal_trace_id_var.reset(token)
        logger.removeHandler(handler)

    output = stream.getvalue().strip()
    assert plaintext_key not in output, "plaintext API key leaked into log output"
    assert "aiiam_***REDACTED***" in output

    record = json.loads(output)
    assert record["causal_trace_id"] == "trace-redaction-test"
    assert record["level"] == "INFO"
    assert "agt-123" in record["message"]  # non-secret context is preserved


def test_untainted_message_passes_through_unchanged():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(TraceIdFilter())
    handler.setFormatter(RedactingJSONFormatter())

    logger = logging.getLogger("test.redaction.clean")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    logger.propagate = False

    try:
        logger.info("agent agt-456 activated")
    finally:
        logger.removeHandler(handler)

    record = json.loads(stream.getvalue().strip())
    assert record["message"] == "agent agt-456 activated"
