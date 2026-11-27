"""FastAPI routers for the audit trail.

No ``from __future__ import annotations`` here: FastAPI resolves the endpoint
annotations (``Request``) at runtime.
"""

import asyncio
from collections.abc import Callable, Sequence
from typing import Any

from .approvals import ApprovalRequest, ApprovalResponse
from .audit import AuditLog, AuditPage
from .hitl import ApprovalBroker, ApprovalDecisionBody, bearer_dependency, resolve_scope

__all__ = ["approval_routes", "create_audit_router"]


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


def approval_routes(
    broker: ApprovalBroker,
    token: str | None = None,
    *,
    require_scope: Callable[[Any], Any] | None = None,
    dependencies: Sequence[Any] = (),
) -> Any:
    """The routes behind :func:`mcp_rbac_gateway.create_approval_router`."""
    try:
        from fastapi import APIRouter, Depends, HTTPException, Request
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "run: pip install 'mcp-rbac-gateway[server]' to use the approval API"
        ) from exc

    router = APIRouter(
        prefix="/approvals",
        tags=["approvals"],
        dependencies=[Depends(bearer_dependency(token, "approval")), *dependencies],
    )

    def visible(record_tenant: str | None, scope: str | None) -> bool:
        return scope is None or record_tenant == scope

    @router.get("", response_model=list[ApprovalRequest])
    async def list_pending(request: Request) -> list[ApprovalRequest]:
        scope = await resolve_scope(require_scope, request)
        return broker.pending(scope)

    @router.get("/{request_id}", response_model=ApprovalRequest)
    async def get_request(request_id: str, request: Request) -> ApprovalRequest:
        scope = await resolve_scope(require_scope, request)
        pending = broker.get(request_id)
        if pending is None or not visible(pending.tenant_id, scope):
            raise HTTPException(status_code=404, detail="no such pending approval")
        return pending

    async def decide(
        request_id: str, approved: bool, body: ApprovalDecisionBody | None, request: Request
    ) -> dict[str, Any]:
        scope = await resolve_scope(require_scope, request)
        record = broker.record(request_id)
        if record is None or not visible(record.request.tenant_id, scope):
            raise HTTPException(status_code=404, detail="no such approval")
        body = body or ApprovalDecisionBody()
        response = ApprovalResponse(
            approved=approved, approver=body.approver or "api", comment=body.comment
        )
        if not broker.resolve(request_id, response):
            current = broker.record(request_id)
            status = current.status.value if current else "gone"
            raise HTTPException(status_code=409, detail=f"approval is already {status}")
        return {"id": request_id, "approved": approved}

    @router.post("/{request_id}/approve")
    async def approve(
        request_id: str, request: Request, body: ApprovalDecisionBody | None = None
    ) -> dict[str, Any]:
        return await decide(request_id, True, body, request)

    @router.post("/{request_id}/deny")
    async def deny(
        request_id: str, request: Request, body: ApprovalDecisionBody | None = None
    ) -> dict[str, Any]:
        return await decide(request_id, False, body, request)

    return router
