"""
Trace Propagation Middleware.

Injects a causal_trace_id into every request so that ALL audit events,
MCP calls, and delegation grants from the same request are linked.

If the calling agent passes an X-Trace-Id header (from their parent
agent's trace), we inherit it. Otherwise we generate a new one.

This is what enables reconstructing the full causal tree:
  Parent Agent (trace: T1)
    → HTTP request to our API (X-Trace-Id: T1)
      → agent_service.activate() audit entry (trace: T1)
      → api_key_service.issue_key() audit entry (trace: T1)
      → mcp_proxy.execute_tool() audit entry (trace: T1)

Without this, each audit entry would have a different trace ID
and you couldn't reconstruct what triggered what.
"""

import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request

from app.core.logging_config import causal_trace_id_var


TRACE_HEADER = "X-Trace-Id"
RESPONSE_TRACE_HEADER = "X-Trace-Id"


class TracePropagationMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next):
        # Inherit from caller if present, generate new if not
        trace_id = request.headers.get(TRACE_HEADER) or str(uuid.uuid4())

        # Validate format (prevent header injection)
        if not self._is_valid_trace_id(trace_id):
            trace_id = str(uuid.uuid4())

        # Bind to request state — services read from here
        request.state.causal_trace_id = trace_id
        # Also bind to the contextvar every log line reads (Slice 14) —
        # a separate mechanism from request.state because log calls deep
        # in a service have no Request object to read state off of.
        # BaseHTTPMiddleware runs dispatch() in a spawned task, so this
        # context is naturally isolated per request/task; no manual
        # reset is needed the way it would be with a shared object.
        causal_trace_id_var.set(trace_id)

        response = await call_next(request)

        # Echo back in response so callers can correlate
        response.headers[RESPONSE_TRACE_HEADER] = trace_id
        return response

    def _is_valid_trace_id(self, trace_id: str) -> bool:
        """
        Validate trace ID format.
        Accept UUID v4 or "jit:<task_id>" for JIT-activated agents.
        Reject anything that looks like a header injection attempt.
        """
        if len(trace_id) > 128:
            return False
        # Must be alphanumeric with hyphens or colons only
        import re
        return bool(re.match(r"^[a-zA-Z0-9\-:_]+$", trace_id))
