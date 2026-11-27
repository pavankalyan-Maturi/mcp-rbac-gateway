"""FastAPI routers for the audit trail.

No ``from __future__ import annotations`` here: FastAPI resolves the endpoint
annotations (``Request``) at runtime.
"""

import asyncio
from collections.abc import Callable, Sequence
from typing import Any

from .audit import AuditLog, AuditPage

__all__ = ["create_audit_router"]


def create_audit_router(
    audit: AuditLog,
    token: str | None = None,
    *,
    require_scope: Callable[[Any], Any] | None = None,
    dependencies: Sequence[Any] = (),
    prefix: str = "/audit",
) -> Any:
    """FastAPI router with ``GET /audit``: a read-only, tenant-safe view of the audit trail.

    Args:
        audit: The audit log to read.
        token: When set, requests must send ``Authorization: Bearer <token>``.
        require_scope: ``(request) -> tenant_id | None``, sync or async. When it
            returns a tenant, that tenant is forced into every query, whatever
            the caller passes as ``tenant_id``, so one tenant can never read
            another's rows. Returning ``None`` means "no restriction" (an
            operator view): make sure your callable only does that for callers
            who may see every tenant. Raise ``HTTPException`` to refuse.
        dependencies: Extra FastAPI dependencies (``[Depends(my_auth)]``), so
            you can reuse your own authentication instead of ``token``.

    Query parameters: ``agent``, ``tool``, ``decision``, ``method``,
    ``blocked_only``, ``since`` (Unix time), ``session_id``, ``request_id``,
    ``tenant_id``, ``trace_id``, ``limit`` (1-500, default 100) and
    ``before_id`` (keyset cursor). The response is an :class:`AuditPage`.
    """
    try:
        from fastapi import APIRouter, Depends, Query, Request
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "run: pip install 'mcp-rbac-gateway[server]' to use the audit API"
        ) from exc

    from .hitl import bearer_dependency, resolve_scope

    router = APIRouter(
        prefix=prefix,
        tags=["audit"],
        dependencies=[Depends(bearer_dependency(token, "audit")), *dependencies],
    )

    @router.get("", response_model=AuditPage)
    async def list_events(
        request: Request,
        agent: str | None = None,
        tool: str | None = None,
        decision: str | None = None,
        method: str | None = None,
        blocked_only: bool = False,
        since: float | None = None,
        session_id: str | None = None,
        request_id: str | None = None,
        tenant_id: str | None = None,
        trace_id: str | None = None,
        limit: int = Query(default=100, ge=1, le=500),
        before_id: int | None = Query(default=None, ge=1),
    ) -> AuditPage:
        scope = await resolve_scope(require_scope, request)
        return await asyncio.to_thread(
            audit.page,
            limit=limit,
            agent_id=agent,
            tool=tool,
            decision=decision,
            method=method,
            blocked_only=blocked_only,
            since=since,
            session_id=session_id,
            request_id=request_id,
            tenant_id=scope if scope is not None else tenant_id,
            trace_id=trace_id,
            before_id=before_id,
        )

    return router
