"""HTTP proxy hooks: context/agent resolvers, fail-closed approvals, dual-era dispatch.

Everything runs in process: the upstream is an ASGI app reached through
``transport=httpx.ASGITransport(app=upstream)``, and the proxy app is driven
the same way.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from mcp_rbac_gateway import (
    ApprovalBroker,
    AuditDecision,
    AutoApprover,
    CallContext,
    DualHttpProxy,
    HttpProxy,
    Sentinel,
    SentinelConfig,
    StatelessHttpProxy,
    create_approval_router,
    create_audit_router,
)
from mcp_rbac_gateway.mcp import LATEST_PROTOCOL_VERSION

MODERN = {"io.modelcontextprotocol/protocolVersion": LATEST_PROTOCOL_VERSION}


def upstream_app() -> FastAPI:
    """Answers every request with which era it saw (by the version header)."""
    app = FastAPI()
    app.state.seen = []

    @app.post("/mcp")
    async def mcp(request: Request) -> JSONResponse:
        msg = await request.json()
        era = request.headers.get("mcp-protocol-version", "none")
        app.state.seen.append((msg["method"], era))
        method = msg["method"]
        if method == "tools/call":
            result: Any = {"content": [{"type": "text", "text": "ok"}]}
        elif method == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {}, "serverInfo": {}}
        else:
            result = {"era": era}
        headers = {"mcp-session-id": "s-1"} if method == "initialize" else {}
        return JSONResponse({"jsonrpc": "2.0", "id": msg["id"], "result": result}, headers=headers)

    return app


def gateway(tmp_path: Path, **hitl: Any) -> Sentinel:
    cfg = SentinelConfig.model_validate(
        {
            "default_agent": "guest",
            "default_action": "deny",
            "agents": {"guest": {"allow": ["echo"]}, "admin": {"allow": ["*"]}},
            "hitl": {"mode": "auto_approve", **hitl},
            "audit": {"path": str(tmp_path / "a.db")},
        }
    )
    return Sentinel(cfg, approver=AutoApprover(True))


def client(app: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gw")


def stateless(method: str, mid: int, **params: Any) -> tuple[dict[str, Any], dict[str, str]]:
    body = {"jsonrpc": "2.0", "id": mid, "method": method, "params": {**params, "_meta": MODERN}}
    headers = {"mcp-protocol-version": LATEST_PROTOCOL_VERSION, "mcp-method": method}
    if method == "tools/call":
        headers["mcp-name"] = params["name"]
    return body, headers


def tenant_from_headers(headers: Mapping[str, str], body: Any) -> CallContext:
    # Stands in for "read tenant_id from the verified JWT".
    tenant = headers.get("x-tenant")
    if tenant is None:
        raise PermissionError("no tenant")
    return CallContext(tenant_id=tenant, labels={"via": "proxy"})


def role_from_bearer(headers: Mapping[str, str]) -> str | None:
    auth = headers.get("authorization", "")
    if not auth.startswith("Bearer role:"):
        raise PermissionError("bad bearer token")
    return auth.removeprefix("Bearer role:")


@pytest.mark.parametrize("cls", [HttpProxy, StatelessHttpProxy])
async def test_context_resolver_tags_allowed_and_blocked_rows(tmp_path: Path, cls: type) -> None:
    s = gateway(tmp_path)
    upstream = upstream_app()
    proxy = cls(
        s,
        "http://upstream/mcp",
        transport=httpx.ASGITransport(app=upstream),
        context_resolver=tenant_from_headers,
    )
    async with client(proxy.build_app()) as c:
        for mid, tool in [(1, "echo"), (2, "shell")]:
            body, headers = stateless("tools/call", mid, name=tool, arguments={})
            r = await c.post("/mcp", json=body, headers={**headers, "x-tenant": "acme"})
            assert r.status_code == 200
        body, headers = stateless("tools/call", 3, name="echo", arguments={})
        assert (await c.post("/mcp", json=body, headers=headers)).status_code == 401

    assert s.audit is not None
    rows = {r.tool: r for r in s.audit.query(tenant_id="acme")}
    assert rows["echo"].decision is AuditDecision.ALLOWED
    assert rows["shell"].decision is AuditDecision.BLOCKED_POLICY
    assert all(r.labels == {"via": "proxy"} for r in rows.values())
    assert {r.request_id for r in rows.values()} == {"1", "2"}
    assert s.audit.count() == 2  # the 401 wrote nothing
    s.close()


async def test_agent_resolver_overrides_identify(tmp_path: Path) -> None:
    s = gateway(tmp_path)
    proxy = StatelessHttpProxy(
        s,
        "http://upstream/mcp",
        transport=httpx.ASGITransport(app=upstream_app()),
        agent_resolver=role_from_bearer,
    )
    async with client(proxy.build_app()) as c:
        body, headers = stateless("tools/call", 1, name="shell", arguments={})
        # X-Sentinel-Agent is ignored once a resolver is set.
        r = await c.post(
            "/mcp",
            json=body,
            headers={**headers, "authorization": "Bearer role:guest", "x-sentinel-agent": "admin"},
        )
        assert r.json()["result"]["isError"] is True
        r = await c.post(
            "/mcp", json=body, headers={**headers, "authorization": "Bearer role:admin"}
        )
        assert r.json()["result"]["content"][0]["text"] == "ok"
        r = await c.post("/mcp", json=body, headers={**headers, "authorization": "Basic x"})
        assert r.status_code == 401
    s.close()


async def test_async_resolvers(tmp_path: Path) -> None:
    s = gateway(tmp_path)

    async def agent(headers: Mapping[str, str]) -> str | None:
        return "admin"

    async def context(headers: Mapping[str, str], body: Any) -> CallContext:
        return CallContext(tenant_id="t-async")

    proxy = StatelessHttpProxy(
        s,
        "http://upstream/mcp",
        transport=httpx.ASGITransport(app=upstream_app()),
        agent_resolver=agent,
        context_resolver=context,
    )
    async with client(proxy.build_app()) as c:
        body, headers = stateless("tools/call", 1, name="shell", arguments={})
        assert "isError" not in (await c.post("/mcp", json=body, headers=headers)).json()["result"]
    assert s.audit is not None
    assert [r.agent_id for r in s.audit.query(tenant_id="t-async")] == ["admin"]
    s.close()


def test_routers_fail_closed(tmp_path: Path) -> None:
    broker = ApprovalBroker()
    with pytest.raises(ValueError, match="no token"):
        create_approval_router(broker)
    s = gateway(tmp_path)
    assert s.audit is not None
    with pytest.raises(ValueError, match="no token"):
        create_audit_router(s.audit)

    def host_auth() -> None:
        raise HTTPException(status_code=401)

    create_approval_router(broker, dependencies=[Depends(host_auth)])
    create_approval_router(broker, "t0ken")
    create_approval_router(broker, allow_unauthenticated=True)
    s.close()


async def test_proxy_refuses_open_approvals_when_calls_wait_for_them(tmp_path: Path) -> None:
    s = gateway(tmp_path, mode="api")
    for cls in (HttpProxy, StatelessHttpProxy, DualHttpProxy):
        with pytest.raises(ValueError, match="approval API"):
            cls(s, "http://upstream/mcp").build_app()
    # A token mounts it, protected.
    app = HttpProxy(s, "http://upstream/mcp", approval_token="t0ken").build_app()
    async with client(app) as c:
        assert (await c.get("/approvals")).status_code == 401
        auth = {"authorization": "Bearer t0ken"}
        assert (await c.get("/approvals", headers=auth)).json() == []
    # Explicitly open.
    app = HttpProxy(s, "http://upstream/mcp", allow_unauthenticated_approvals=True).build_app()
    async with client(app) as c:
        assert (await c.get("/approvals")).json() == []
    s.close()


async def test_dual_era_proxy_routes_by_protocol_version(tmp_path: Path) -> None:
    s = gateway(tmp_path)
    upstream = upstream_app()
    proxy = DualHttpProxy(s, "http://upstream/mcp", transport=httpx.ASGITransport(app=upstream))
    async with client(proxy.build_app()) as c:
        # 2025-era: initialize has no version header yet.
        init = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {}},
        }
        r = await c.post("/mcp", json=init)
        assert r.status_code == 200 and r.headers["mcp-session-id"] == "s-1"
        # A later 2025-era request in that session: legacy path, no header checks.
        legacy = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        r = await c.post(
            "/mcp",
            json=legacy,
            headers={"mcp-protocol-version": "2025-06-18", "mcp-session-id": "s-1"},
        )
        assert r.status_code == 200

        # 2026-era: server/discover takes the stateless path.
        body, headers = stateless("server/discover", 3)
        r = await c.post("/mcp", json=body, headers=headers)
        assert r.status_code == 200 and r.json()["result"]["era"] == LATEST_PROTOCOL_VERSION
        # ... including its header checks (Mcp-Method must match the body).
        r = await c.post("/mcp", json=body, headers={**headers, "mcp-method": "tools/list"})
        assert r.status_code == 400 and r.json()["error"]["code"] == -32020
        assert (await c.get("/healthz")).json() == {"status": "ok"}

    assert upstream.state.seen == [
        ("initialize", "none"),
        ("tools/list", "2025-06-18"),
        ("server/discover", LATEST_PROTOCOL_VERSION),
    ]
    assert s.audit is not None
    s.close()
