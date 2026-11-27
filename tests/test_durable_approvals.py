"""Durable, multi-instance approvals: stores, resume_call and the scoped approval API."""

from __future__ import annotations

import asyncio
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from mcp_rbac_gateway import (
    ApprovalBroker,
    ApprovalConflict,
    ApprovalRequest,
    ApprovalResponse,
    ApprovalStatus,
    AuditDecision,
    MemoryApprovalStore,
    Sentinel,
    SentinelConfig,
    SqliteApprovalStore,
    ToolBlockedError,
    call_context,
    create_approval_router,
)

CONFIG = """
default_action: deny
agents:
  ops:
    allow: ["*"]
    require_approval: ["delete_*"]
hitl:
  mode: api
  store: sqlite
  timeout_seconds: TIMEOUT
audit:
  path: DB
"""


def make(tmp_path: Path, timeout: float = 10) -> Sentinel:
    text = CONFIG.replace("DB", str(tmp_path / "audit.db")).replace("TIMEOUT", str(timeout))
    cfg = SentinelConfig.from_yaml_string(text)
    cfg.hitl.timeout_seconds = timeout
    s = Sentinel(cfg)
    s.broker.poll_interval = 0.01
    s.broker.max_poll_interval = 0.05
    return s


async def deleted(args: dict[str, Any]) -> str:
    return f"deleted {args['path']}"


async def wait_for_pending(s: Sentinel, n: int = 1) -> list[ApprovalRequest]:
    for _ in range(300):
        pending = s.broker.pending()
        if len(pending) >= n:
            return pending
        await asyncio.sleep(0.01)
    raise AssertionError("no pending approval appeared")


# ----------------------------------------------------------------------- stores


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_store_first_writer_wins(kind: str, tmp_path: Path) -> None:
    store = MemoryApprovalStore() if kind == "memory" else SqliteApprovalStore(tmp_path / "a.db")
    req = ApprovalRequest(agent_id="a", tool="t", arguments={}, reason="r", tenant_id="acme")
    store.put(req)
    assert [r.id for r in store.list_pending()] == [req.id]
    assert [r.id for r in store.list_pending("acme")] == [req.id]
    assert store.list_pending("globex") == []
    assert store.resolve(req.id, ApprovalResponse(approved=True, approver="alice"))
    assert not store.resolve(req.id, ApprovalResponse(approved=False, approver="bob"))
    record = store.get(req.id)
    assert record is not None and record.status is ApprovalStatus.APPROVED
    assert record.response is not None and record.response.approver == "alice"
    assert store.list_pending() == []


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_store_expiry(kind: str, tmp_path: Path) -> None:
    store = MemoryApprovalStore() if kind == "memory" else SqliteApprovalStore(tmp_path / "a.db")
    req = ApprovalRequest(
        agent_id="a",
        tool="t",
        arguments={},
        reason="r",
        created_at=time.time() - 10,
        timeout_seconds=1,
    )
    store.put(req)
    assert store.list_pending() == []
    record = store.get(req.id)
    assert record is not None and record.status is ApprovalStatus.EXPIRED
    assert not store.resolve(req.id, ApprovalResponse(approved=True))
    assert store.expire() == [req.id]


def test_concurrent_resolve_has_one_winner(tmp_path: Path) -> None:
    path = tmp_path / "a.db"
    req = ApprovalRequest(agent_id="a", tool="t", arguments={}, reason="r")
    SqliteApprovalStore(path).put(req)
    stores = [SqliteApprovalStore(path) for _ in range(8)]
    wins: list[bool] = []
    threads = [
        threading.Thread(
            target=lambda st=st: wins.append(st.resolve(req.id, ApprovalResponse(approved=True)))
        )
        for st in stores
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(wins) == [False] * 7 + [True]


# ------------------------------------------------------------------ cross-process


async def test_approve_from_a_second_instance(tmp_path: Path) -> None:
    a, b = make(tmp_path), make(tmp_path)
    with call_context(tenant_id="acme", request_id="call-1"):
        task = asyncio.create_task(a.call("delete_file", {"path": "/x"}, deleted, agent_id="ops"))
        [pending] = await wait_for_pending(b)
    assert (pending.tenant_id, pending.request_id) == ("acme", "call-1")
    assert b.broker.resolve(pending.id, ApprovalResponse(approved=True, approver="alice"))
    assert await task == "deleted /x"
    assert a.audit is not None
    rows = a.audit.query(request_id="call-1")
    assert [(e.decision, e.approval_id) for e in rows] == [
        (AuditDecision.APPROVED, pending.id),
        (AuditDecision.PENDING_APPROVAL, pending.id),
    ]
    assert rows[0].approver == "alice" and rows[0].tenant_id == "acme"
    a.close()
    b.close()


async def test_restart_while_pending(tmp_path: Path) -> None:
    a = make(tmp_path)
    task = asyncio.create_task(a.call("delete_file", {"path": "/y"}, deleted, agent_id="ops"))
    await wait_for_pending(a)
    # "Restart": a brand-new broker and store on the same file.
    fresh = ApprovalBroker(SqliteApprovalStore(tmp_path / "audit.db"))
    [pending] = fresh.pending()
    assert fresh.resolve(pending.id, ApprovalResponse(approved=False, approver="bob"))
    with pytest.raises(ToolBlockedError) as info:
        await task  # the original waiter is still alive and sees the decision
    assert info.value.decision is AuditDecision.DENIED_BY_HUMAN
    a.close()


async def test_timeout_is_recorded(tmp_path: Path) -> None:
    s = make(tmp_path, timeout=0.2)
    with pytest.raises(ToolBlockedError) as info:
        await s.call("delete_file", {"path": "/z"}, deleted, agent_id="ops")
    assert info.value.decision is AuditDecision.APPROVAL_TIMEOUT
    assert s.audit is not None
    assert [e.decision for e in s.audit.query()] == [
        AuditDecision.APPROVAL_TIMEOUT,
        AuditDecision.PENDING_APPROVAL,
    ]
    s.close()


# ---------------------------------------------------------- wait=False / resume


async def test_wait_false_then_resume_approved(tmp_path: Path) -> None:
    s = make(tmp_path)
    with call_context(tenant_id="acme", session_id="conv-1", request_id="tc-9"):
        verdict = await s.check_call("ops", "delete_file", {"path": "/a"}, wait=False)
    assert verdict.pending and verdict.approval_id and not verdict.allowed
    # ... the host checkpoints, waits hours, then resumes in another process:
    other = make(tmp_path)
    out = await other.resume_call(
        verdict.approval_id, ApprovalResponse(approved=True, approver="carol"), deleted
    )
    assert out == "deleted /a"
    assert other.audit is not None
    rows = other.audit.query(request_id="tc-9")
    assert [e.decision for e in rows] == [
        AuditDecision.APPROVED,
        AuditDecision.PENDING_APPROVAL,
    ]
    assert rows[0].approver == "carol"
    assert {(e.tenant_id, e.session_id) for e in rows} == {("acme", "conv-1")}
    with pytest.raises(ApprovalConflict):
        await other.resume_call(verdict.approval_id, True)
    s.close()
    other.close()


async def test_wait_false_then_resume_denied(tmp_path: Path) -> None:
    s = make(tmp_path)
    verdict = await s.check_call("ops", "delete_file", {"path": "/b"}, wait=False)
    assert verdict.approval_id
    resumed = await s.resume_call(
        verdict.approval_id, ApprovalResponse(approved=False, approver="dan")
    )
    assert resumed.decision is AuditDecision.DENIED_BY_HUMAN and resumed.approver == "dan"
    assert s.audit is not None
    assert s.audit.query()[0].decision is AuditDecision.DENIED_BY_HUMAN
    s.close()


def test_resume_call_sync(tmp_path: Path) -> None:
    s = make(tmp_path)
    verdict = s.check_call_sync("ops", "delete_file", {"path": "/c"}, wait=False)
    assert verdict.approval_id
    out = s.resume_call_sync(verdict.approval_id, True, lambda a: f"gone {a['path']}")
    assert out == "gone /c"
    s.close()


async def test_resume_after_expiry_is_a_timeout(tmp_path: Path) -> None:
    s = make(tmp_path, timeout=0.05)
    verdict = await s.check_call("ops", "delete_file", {"path": "/d"}, wait=False)
    assert verdict.approval_id
    await asyncio.sleep(0.1)
    resumed = await s.resume_call(verdict.approval_id, True)
    assert resumed.decision is AuditDecision.APPROVAL_TIMEOUT
    s.close()


async def test_call_with_wait_false_raises_pending(tmp_path: Path) -> None:
    s = make(tmp_path)
    with pytest.raises(ToolBlockedError) as info:
        await s.call("delete_file", {"path": "/e"}, deleted, agent_id="ops", wait=False)
    assert info.value.decision is AuditDecision.PENDING_APPROVAL
    assert info.value.verdict is not None and info.value.verdict.approval_id
    s.close()


# ------------------------------------------------------------------- the router


def tenant(request: Request) -> str | None:
    return request.headers.get("x-tenant")


def test_router_double_approve_and_scope(tmp_path: Path) -> None:
    s = make(tmp_path)
    with call_context(tenant_id="acme"):
        a = s.check_call_sync("ops", "delete_file", {"path": "/1"}, wait=False)
    with call_context(tenant_id="globex"):
        g = s.check_call_sync("ops", "delete_file", {"path": "/2"}, wait=False)
    app = FastAPI()
    app.include_router(create_approval_router(s.broker, require_scope=tenant))
    client = TestClient(app)
    acme_h, globex_h = {"x-tenant": "acme"}, {"x-tenant": "globex"}

    assert [r["id"] for r in client.get("/approvals", headers=acme_h).json()] == [a.approval_id]
    assert [r["id"] for r in client.get("/approvals", headers=globex_h).json()] == [g.approval_id]
    assert client.get(f"/approvals/{g.approval_id}", headers=acme_h).status_code == 404
    assert client.post(f"/approvals/{g.approval_id}/approve", headers=acme_h).status_code == 404

    first = client.post(
        f"/approvals/{a.approval_id}/approve", headers=acme_h, json={"approver": "x"}
    )
    assert first.status_code == 200
    second = client.post(f"/approvals/{a.approval_id}/deny", headers=acme_h)
    assert second.status_code == 409 and "approved" in second.json()["detail"]
    record = s.broker.record(str(a.approval_id))
    assert record is not None and record.response is not None and record.response.approver == "x"
    # No header: the scope hook returns None, i.e. an unscoped operator view.
    assert [r["id"] for r in client.get("/approvals").json()] == [g.approval_id]
    s.close()
