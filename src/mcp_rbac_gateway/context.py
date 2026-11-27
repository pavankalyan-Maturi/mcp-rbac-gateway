"""Per-call request context: tenant, session, tool-call id and trace.

A multi-tenant host needs every audit row (and every approval request) tagged
with *who* the call was made for. Bind that once around the agent run::

    with call_context(tenant_id="acme", session_id="conv-42", request_id=tool_call.id):
        await guarded_tool(...)

and every row written by :meth:`Sentinel.call`, ``@guard`` and
:meth:`Sentinel.check_call` carries it. The context is a
:class:`contextvars.ContextVar`, so it follows ``await`` and
``asyncio.to_thread`` but never leaks between concurrent tasks.
"""

from __future__ import annotations

import contextvars
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field, fields, replace
from types import MappingProxyType
from typing import Any

__all__ = ["CallContext", "call_context", "current_call_context", "otel_traceparent"]


@dataclass(frozen=True)
class CallContext:
    """Request context recorded with a call. Every field is optional.

    Attributes:
        session_id: The host's conversation or session id.
        request_id: The tool-call id (e.g. the LLM's ``tool_call.id``).
        traceparent: A W3C ``traceparent``. When missing, it is read from the
            current OpenTelemetry span if ``opentelemetry`` is installed.
        tenant_id: The tenant the call is made for. Used to scope audit and
            approval queries.
        labels: Free-form string labels stored with the audit row.
    """

    session_id: str | None = None
    request_id: str | None = None
    traceparent: str | None = None
    tenant_id: str | None = None
    labels: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "labels", MappingProxyType(dict(self.labels)))

    def merged(self, inner: CallContext) -> CallContext:
        """``inner`` on top of ``self``: inner fields win when set, labels are combined."""
        updates: dict[str, Any] = {
            f.name: getattr(inner, f.name)
            for f in fields(self)
            if f.name != "labels" and getattr(inner, f.name) is not None
        }
        updates["labels"] = {**self.labels, **inner.labels}
        return replace(self, **updates)

    def with_trace(self) -> CallContext:
        """Fill ``traceparent`` from OpenTelemetry when it is not set."""
        if self.traceparent is not None:
            return self
        traceparent = otel_traceparent()
        return replace(self, traceparent=traceparent) if traceparent else self


_current_call: contextvars.ContextVar[CallContext | None] = contextvars.ContextVar(
    "mcp_rbac_gateway_call_context", default=None
)


def current_call_context() -> CallContext | None:
    """The context bound with :func:`call_context`, if any."""
    return _current_call.get()


@contextmanager
def call_context(
    context: CallContext | None = None,
    *,
    session_id: str | None = None,
    request_id: str | None = None,
    traceparent: str | None = None,
    tenant_id: str | None = None,
    labels: Mapping[str, str] | None = None,
) -> Iterator[CallContext]:
    """Bind request context for every guarded call in this block.

    Nested blocks inherit the outer fields and override the ones they set.
    """
    inner = context or CallContext(
        session_id=session_id,
        request_id=request_id,
        traceparent=traceparent,
        tenant_id=tenant_id,
        labels=labels or {},
    )
    outer = _current_call.get()
    effective = outer.merged(inner) if outer is not None else inner
    token = _current_call.set(effective)
    try:
        yield effective
    finally:
        _current_call.reset(token)


def otel_traceparent() -> str | None:
    """The current OpenTelemetry span as a W3C ``traceparent``, or None.

    OpenTelemetry is optional: without it (or without an active, valid span)
    this returns None.
    """
    try:
        from opentelemetry import trace  # type: ignore[import-not-found,unused-ignore]
    except ImportError:
        return None
    try:
        span_context = trace.get_current_span().get_span_context()
    except Exception:  # pragma: no cover - a broken tracer must never break a call
        return None
    if not getattr(span_context, "is_valid", False):
        return None
    flags = int(getattr(span_context, "trace_flags", 0)) & 0xFF
    return f"00-{span_context.trace_id:032x}-{span_context.span_id:016x}-{flags:02x}"
