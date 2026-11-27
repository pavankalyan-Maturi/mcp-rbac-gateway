"""Tenant-safe audit queries, schema versioning and the audit router."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from mcp_rbac_gateway import (
    ApprovalBroker,
    AuditDecision,
    AuditEvent,
    AuditLog,
    create_approval_router,
    create_audit_router,
)
from mcp_rbac_gateway.audit import SCHEMA_VERSION


def event(
    tenant: str, request_id: str, decision: AuditDecision = AuditDecision.ALLOWED
) -> AuditEvent:
    return AuditEvent(
        agent_id="agent",
        tool="echo",
        decision=decision,
        tenant_id=tenant,
        session_id=f"sess-{tenant}",
        request_id=request_id,
    )


@pytest.fixture
def log(tmp_path: Path) -> AuditLog:
    audit = AuditLog(tmp_path / "audit.db")
    for i in range(5):
        audit.record_sync(event("acme", f"a{i}"))
        audit.record_sync(event("globex", f"g{i}", AuditDecision.BLOCKED_POLICY))
    return audit


def test_filter_by_tenant_session_and_request(log: AuditLog) -> None:
    assert {e.tenant_id for e in log.query(tenant_id="acme")} == {"acme"}
    assert len(log.query(tenant_id="acme")) == 5
    assert len(log.query(session_id="sess-globex")) == 5
    [one] = log.query(request_id="g3")
    assert one.tenant_id == "globex"
    assert log.query(tenant_id="acme", request_id="g3") == []


def test_keyset_pagination_is_stable_under_writes(log: AuditLog) -> None:
    first = log.page(tenant_id="acme", limit=2)
    assert [e.request_id for e in first.events] == ["a4", "a3"]
    for i in range(5, 8):  # new rows land while the client pages
        log.record_sync(event("acme", f"a{i}"))
    second = log.page(tenant_id="acme", limit=2, before_id=first.next_before_id)
    third = log.page(tenant_id="acme", limit=2, before_id=second.next_before_id)
    assert [e.request_id for e in second.events] == ["a2", "a1"]
    assert [e.request_id for e in third.events] == ["a0"]
    assert third.next_before_id is None


def test_schema_version_is_set(log: AuditLog) -> None:
    assert log.schema_version == SCHEMA_VERSION == 3


V020_SCHEMA = """
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, agent_id TEXT NOT NULL,
    tool TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '',
    latency_ms REAL, transport TEXT NOT NULL DEFAULT 'python', request_id TEXT,
    session_id TEXT, approver TEXT, arguments TEXT, result TEXT, findings TEXT,
    redactions INTEGER NOT NULL DEFAULT 0, injection_score REAL NOT NULL DEFAULT 0,
    is_error INTEGER NOT NULL DEFAULT 0, method TEXT NOT NULL DEFAULT 'tools/call',
    protocol_version TEXT, client_name TEXT, client_version TEXT, traceparent TEXT,
    tracestate TEXT, meta TEXT
);
INSERT INTO events (ts, agent_id, tool, decision, session_id, traceparent)
VALUES (1700000000, 'old-agent', 'read_file', 'allowed', 's-old', '00-abc-def-01');
"""


def test_migrates_a_0_2_0_database(tmp_path: Path) -> None:
    path = tmp_path / "v020.db"
    conn = sqlite3.connect(path)
    conn.executescript(V020_SCHEMA)
    conn.close()
    with AuditLog(path) as log:
        assert log.schema_version == SCHEMA_VERSION
        [old] = log.query()
        assert (old.agent_id, old.session_id, old.traceparent) == (
            "old-agent",
            "s-old",
            "00-abc-def-01",
        )
        assert old.tenant_id is None and old.labels == {} and old.approval_id is None
        log.record_sync(event("acme", "new"))
        assert len(log.query(tenant_id="acme")) == 1


def test_refuses_a_newer_schema(tmp_path: Path) -> None:
    path = tmp_path / "future.db"
    AuditLog(path).close()
    conn = sqlite3.connect(path)
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    conn.close()
    with pytest.raises(RuntimeError, match="upgrade the package"):
        AuditLog(path)


# ----------------------------------------------------------------------- router


def tenant_from_header(request: Request) -> str | None:
    tenant = request.headers.get("x-tenant")
    if tenant is None:
        raise HTTPException(status_code=403, detail="no tenant")
    return None if tenant == "*operator*" else tenant


def make_app(log: AuditLog, **kwargs: object) -> TestClient:
    app = FastAPI()
    kwargs.setdefault("allow_unauthenticated", "token" not in kwargs)
    app.include_router(create_audit_router(log, **kwargs))  # type: ignore[arg-type]
    return TestClient(app)


def test_router_filters_and_paginates(log: AuditLog) -> None:
    client = make_app(log)
    body = client.get("/audit", params={"tenant_id": "globex", "limit": 3}).json()
    assert [e["request_id"] for e in body["events"]] == ["g4", "g3", "g2"]
    body = client.get(
        "/audit", params={"tenant_id": "globex", "limit": 3, "before_id": body["next_before_id"]}
    ).json()
    assert [e["request_id"] for e in body["events"]] == ["g1", "g0"]
    assert client.get("/audit", params={"limit": 501}).status_code == 422
    blocked = client.get("/audit", params={"blocked_only": True}).json()["events"]
    assert {e["tenant_id"] for e in blocked} == {"globex"}


def test_forced_scope_ignores_tenant_parameter(log: AuditLog) -> None:
    client = make_app(log, require_scope=tenant_from_header)
    rows = client.get(
        "/audit", params={"tenant_id": "globex"}, headers={"x-tenant": "acme"}
    ).json()["events"]
    assert rows and {e["tenant_id"] for e in rows} == {"acme"}
    # Asking for another tenant's request id finds nothing.
    assert (
        client.get("/audit", params={"request_id": "g1"}, headers={"x-tenant": "acme"}).json()[
            "events"
        ]
        == []
    )
    assert client.get("/audit").status_code == 403
    operator = client.get("/audit", headers={"x-tenant": "*operator*"}).json()["events"]
    assert {e["tenant_id"] for e in operator} == {"acme", "globex"}


async def async_scope(request: Request) -> str:
    return "globex"


def test_async_scope(log: AuditLog) -> None:
    rows = make_app(log, require_scope=async_scope).get("/audit").json()["events"]
    assert {e["tenant_id"] for e in rows} == {"globex"}


def test_bearer_token(log: AuditLog) -> None:
    client = make_app(log, token="s3cret")
    assert client.get("/audit").status_code == 401
    assert client.get("/audit", headers={"Authorization": "Bearer s3cret"}).status_code == 200


def test_host_dependency_blocks_both_routers(log: AuditLog) -> None:
    def host_auth(request: Request) -> None:
        if request.headers.get("x-session") != "valid":
            raise HTTPException(status_code=401, detail="login required")

    app = FastAPI()
    app.include_router(create_audit_router(log, dependencies=[Depends(host_auth)]))
    app.include_router(create_approval_router(ApprovalBroker(), dependencies=[Depends(host_auth)]))
    client = TestClient(app)
    assert client.get("/audit").status_code == 401
    assert client.get("/approvals").status_code == 401
    ok = {"x-session": "valid"}
    assert client.get("/audit", headers=ok).status_code == 200
    assert client.get("/approvals", headers=ok).status_code == 200
