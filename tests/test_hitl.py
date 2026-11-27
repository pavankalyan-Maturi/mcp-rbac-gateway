from __future__ import annotations

import asyncio
import io

import httpx
import pytest

from mcp_rbac_gateway import (
    ApprovalBroker,
    ApprovalGate,
    ApprovalRequest,
    ApprovalResponse,
    AuditDecision,
    CallbackApprover,
    CLIApprover,
    WebhookApprover,
    create_approval_router,
)
from mcp_rbac_gateway.config import HitlConfig, WebhookConfig


def req(**kw: object) -> ApprovalRequest:
    base = {"agent_id": "a", "tool": "delete_file", "arguments": {"path": "/x"}, "reason": "r"}
    return ApprovalRequest.model_validate({**base, **kw})


def test_approval_reason_sources() -> None:
    gate = ApprovalGate(
        HitlConfig.model_validate(
            {
                "tools": ["shell_*"],
                "rules": [{"tool": "run_sql", "when": {"query": r"(?i)\bdrop\b"}}],
            }
        ),
        approver=CallbackApprover(lambda r: True),
    )
    assert gate.approval_reason("shell_exec", {}) is not None
    assert gate.approval_reason("run_sql", {"query": "DROP TABLE users"}) is not None
    assert gate.approval_reason("run_sql", {"query": "select 1"}) is None
    assert gate.approval_reason("run_sql", {}) is None
    assert gate.approval_reason("rm", {}, annotations={"destructiveHint": True}) is not None
    assert gate.approval_reason("rm", {}, annotations={"destructiveHint": False}) is None


def test_disabled_gate_never_asks() -> None:
    gate = ApprovalGate(
        HitlConfig(enabled=False, tools=["*"]), approver=CallbackApprover(lambda r: True)
    )
    assert gate.approval_reason("anything", {}) is None


async def test_review_outcomes() -> None:
    approve = ApprovalGate(HitlConfig(), CallbackApprover(lambda r: True, approver="alice"))
    out = await approve.review("a", "t", {}, "because")
    assert out.decision is AuditDecision.APPROVED and out.approver == "alice"

    deny = ApprovalGate(
        HitlConfig(),
        CallbackApprover(
            lambda r: ApprovalResponse(approved=False, approver="bob", comment="no way")
        ),
    )
    out = await deny.review("a", "t", {}, "because")
    assert out.decision is AuditDecision.DENIED_BY_HUMAN
    assert "bob" in out.reason and "no way" in out.reason


async def test_timeout_fails_closed() -> None:
    async def never(_: ApprovalRequest) -> bool:
        await asyncio.sleep(10)
        return True

    gate = ApprovalGate(HitlConfig(timeout_seconds=0.05), CallbackApprover(never))
    out = await gate.review("a", "t", {}, "r")
    assert out.decision is AuditDecision.APPROVAL_TIMEOUT


@pytest.mark.parametrize(
    ("answer", "approved"), [("y\n", True), ("YES\n", True), ("n\n", False), ("\n", False)]
)
async def test_cli_approver(answer: str, approved: bool) -> None:
    out = io.StringIO()
    approver = CLIApprover(input_stream=io.StringIO(answer), output_stream=out)
    resp = await approver.request_approval(req())
    assert resp.approved is approved
    assert "delete_file" in out.getvalue() and "[y/N]" in out.getvalue()


async def test_cli_approver_without_tty_denies(monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins

    real_open = builtins.open

    def fake_open(path, *a, **kw):  # type: ignore[no-untyped-def]
        if path == "/dev/tty":
            raise OSError("no tty")
        return real_open(path, *a, **kw)

    monkeypatch.setattr(builtins, "open", fake_open)
    gate = ApprovalGate(HitlConfig(), CLIApprover())
    out = await gate.review("a", "t", {}, "r")
    assert out.decision is AuditDecision.DENIED_BY_HUMAN
    assert "unavailable" in out.reason


async def test_webhook_inline_decision() -> None:
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        seen.append(json.loads(request.content))
        return httpx.Response(200, json={"approved": True, "approver": "slack:carol"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    approver = WebhookApprover(
        WebhookConfig(url="https://hooks.test/approve", callback_base_url="https://sentinel.test"),
        client=client,
    )
    resp = await approver.request_approval(req())
    assert resp.approved and resp.approver == "slack:carol"
    payload = seen[0]
    assert payload["type"] == "mcp_rbac_gateway.approval_request"
    assert payload["approve_url"].startswith("https://sentinel.test/approvals/")
    assert approver.broker.pending() == []  # cleaned up


async def test_webhook_async_decision_via_router() -> None:
    from fastapi import FastAPI

    broker = ApprovalBroker()
    hook_client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(202)))
    approver = WebhookApprover(
        WebhookConfig(url="https://hooks.test"), broker=broker, client=hook_client
    )
    app = FastAPI()
    app.include_router(create_approval_router(broker, token="s3cret"))
    api = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")

    task = asyncio.create_task(approver.request_approval(req(tool="drop_table")))
    for _ in range(100):
        if broker.pending():
            break
        await asyncio.sleep(0.01)

    assert (await api.get("/approvals")).status_code == 401
    auth = {"Authorization": "Bearer s3cret"}
    pending = (await api.get("/approvals", headers=auth)).json()
    assert [p["tool"] for p in pending] == ["drop_table"]
    rid = pending[0]["id"]
    assert (await api.get(f"/approvals/{rid}", headers=auth)).json()["tool"] == "drop_table"
    r = await api.post(
        f"/approvals/{rid}/deny", headers=auth, json={"approver": "dave", "comment": "nope"}
    )
    assert r.status_code == 200
    resp = await task
    assert resp.approved is False and resp.approver == "dave" and resp.comment == "nope"
    # Already decided: 409 since 0.3.0 (404 before).
    assert (await api.post(f"/approvals/{rid}/approve", headers=auth)).status_code == 409
    assert (await api.post("/approvals/nope/approve", headers=auth)).status_code == 404


async def test_webhook_failure_is_unavailable() -> None:
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    gate = ApprovalGate(
        HitlConfig(mode="webhook"),
        WebhookApprover(WebhookConfig(url="https://hooks.test"), client=client),
    )
    out = await gate.review("a", "t", {}, "r")
    assert out.decision is AuditDecision.DENIED_BY_HUMAN
