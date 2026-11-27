"""A multi-tenant host: per-tenant audit, durable approvals, and an external pause.

Run it:

    pip install "mcp-rbac-gateway[server]"
    APPROVAL_TOKEN=... AUDIT_TOKEN=... uvicorn examples.multi_tenant:create_app --factory

What it shows:

* ``call_context`` tags every audit row with the tenant and the tool-call id.
* ``create_audit_router(require_scope=...)`` forces the caller's tenant into
  every audit query, so one tenant can never read another's rows.
* ``hitl.store: sqlite`` keeps pending approvals in the audit database, so a
  restart loses nothing and any replica can decide them.
* ``check_call(..., wait=False)`` returns at once with ``pending_approval``;
  the host pauses its own way (here: it stores the id and answers 202, as a
  LangGraph ``interrupt`` or a Temporal signal would) and finishes later with
  ``resume_call``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

from mcp_rbac_gateway import (
    ApprovalConflict,
    ApprovalResponse,
    AuditDecision,
    Sentinel,
    SentinelConfig,
    ToolDenial,
    call_context,
    create_audit_router,
)

POLICY = {
    "default_agent": "member",
    "agents": {
        "member": {"allow": ["read_*", "search"]},
        "admin": {"inherits": ["member"], "allow": ["delete_*"], "require_approval": ["delete_*"]},
    },
    "hitl": {"mode": "api", "store": "sqlite", "timeout_seconds": 3600},
}

# Stand-ins for the host's own tools.
TOOLS: dict[str, Any] = {
    "read_doc": lambda args: f"contents of {args['doc']}",
    "delete_doc": lambda args: f"deleted {args['doc']}",
}


class ToolCall(BaseModel):
    id: str  # the model's tool_call.id
    name: str
    arguments: dict[str, Any] = {}


class Decision(BaseModel):
    approved: bool
    approver: str


def tenant_of(x_tenant: str = Header()) -> str:
    """Stands in for "the tenant claim of the caller's verified JWT"."""
    return x_tenant


def create_app(audit_path: str | Path = ".sentinel/tenants.db") -> FastAPI:
    config = SentinelConfig.model_validate({**POLICY, "audit": {"path": str(audit_path)}})
    gateway = Sentinel(config)
    app = FastAPI(title="multi-tenant host")
    app.state.gateway = gateway
    # approval id -> (tenant, call). This is the host's own checkpoint (a
    # LangGraph checkpointer, a Temporal workflow): it holds the raw arguments,
    # which the gateway only ever stores redacted.
    paused: dict[str, tuple[str, ToolCall]] = {}

    async def audit_scope(request: Request) -> str:
        tenant = request.headers.get("x-tenant")
        if not tenant:
            raise HTTPException(status_code=403, detail="no tenant")
        return tenant  # forced into every audit query

    def host_auth(authorization: str = Header(default="")) -> None:
        if authorization != f"Bearer {os.environ.get('AUDIT_TOKEN', 'dev')}":
            raise HTTPException(status_code=401)

    assert gateway.audit is not None
    app.include_router(
        create_audit_router(
            gateway.audit, require_scope=audit_scope, dependencies=[Depends(host_auth)]
        )
    )

    @app.post("/agents/{role}/tools")
    async def run_tool(role: str, call: ToolCall, tenant: str = Depends(tenant_of)) -> Any:
        fn = TOOLS[call.name]

        async def run(args: dict[str, Any]) -> Any:
            return fn(args)

        with call_context(tenant_id=tenant, session_id=f"{tenant}:conv", request_id=call.id):
            out = await gateway.call(
                call.name, call.arguments, run, agent_id=role, wait=False, on_block="result"
            )
        if not isinstance(out, ToolDenial):
            return {"status": "ok", "result": out}
        if out.decision is AuditDecision.PENDING_APPROVAL:
            # Pause the host's own way; nothing waits in this process.
            assert out.approval_id is not None
            paused[out.approval_id] = (tenant, call)
            return {"status": "paused", "approval_id": out.approval_id}
        return {"status": "denied", "message": out.to_text()}  # safe to hand to the model

    @app.post("/approvals/{approval_id}")
    async def decide(approval_id: str, body: Decision, tenant: str = Depends(tenant_of)) -> Any:
        owner, call = paused.get(approval_id, (None, None))
        if owner != tenant or call is None:
            raise HTTPException(status_code=404)
        fn = TOOLS[call.name]

        async def run(args: dict[str, Any]) -> Any:
            return fn(args)

        response = ApprovalResponse(approved=body.approved, approver=body.approver)
        try:
            if not body.approved:
                verdict = await gateway.resume_call(approval_id, response)
                return {"status": "denied", "decision": verdict.decision.value}
            result = await gateway.resume_call(approval_id, response, run)
        except ApprovalConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        paused.pop(approval_id, None)
        return {"status": "ok", "result": result}

    return app
