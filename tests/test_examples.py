"""The examples are part of the product: make sure they keep working."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import httpx
import pytest

pytest.importorskip("langgraph")

EXAMPLES = Path(__file__).parent.parent / "examples"


def load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"examples_{name}", EXAMPLES / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_example_config_validates() -> None:
    from mcp_rbac_gateway import load_config

    cfg = load_config(EXAMPLES / "sentinel.yaml")
    assert {"guest", "support-bot", "ops-agent"} <= set(cfg.agents)


async def test_langgraph_example(tmp_path: Path) -> None:
    from langchain_core.messages import HumanMessage, ToolMessage

    from mcp_rbac_gateway import AuditDecision, Sentinel, agent_context, load_config

    mod = load("langgraph_agent")
    cfg = load_config(EXAMPLES / "sentinel.yaml")
    cfg.audit.path = str(tmp_path / "audit.db")
    sentinel = Sentinel(cfg)
    graph = mod.build_graph(sentinel, mod.ScriptedModel(script=mod.DEMO_SCRIPT))
    with agent_context("support-bot"):
        state = await graph.ainvoke({"messages": [HumanMessage("go")]})
    outputs = [str(m.content) for m in state["messages"] if isinstance(m, ToolMessage)]
    assert len(outputs) == 6
    assert "blocked_injection" in outputs[0]
    assert "jane.doe@example.com" not in outputs[1] and "[REDACTED:email]" in outputs[1]
    assert "blocked_policy" in outputs[2]
    assert "[REDACTED:aws_access_key]" in outputs[3]
    assert "blocked_policy" in outputs[4] and "blocked_policy" in outputs[5]
    assert sentinel.audit is not None
    decisions = [e.decision for e in reversed(sentinel.audit.query())]
    assert decisions == [
        AuditDecision.BLOCKED_INJECTION,
        AuditDecision.ALLOWED,
        AuditDecision.BLOCKED_POLICY,
        AuditDecision.ALLOWED,
        AuditDecision.BLOCKED_POLICY,
        AuditDecision.BLOCKED_POLICY,
    ]
    assert {e.agent_id for e in sentinel.audit.query()} == {"support-bot"}
    sentinel.close()


@pytest.fixture
def fastapi_example(tmp_path: Path):  # type: ignore[no-untyped-def]
    mod = load("fastapi_app")
    app = mod.create_app(audit_path=str(tmp_path / "audit.db"))
    yield app
    app.state.sentinel.close()


async def test_fastapi_direct_tools(fastapi_example) -> None:  # type: ignore[no-untyped-def]
    transport = httpx.ASGITransport(app=fastapi_example)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post(
            "/tools/read_file",
            json={"path": "docs/ops/keys.md"},
            headers={"X-Agent-Id": "support-bot"},
        )
        assert r.status_code == 200 and "[REDACTED:aws_access_key]" in r.json()["result"]
        r = await c.post(
            "/tools/delete_file",
            json={"path": "docs/refunds.md"},
            headers={"X-Agent-Id": "support-bot"},
        )
        assert r.status_code == 403 and r.json()["detail"]["decision"] == "blocked_policy"
        r = await c.post("/tools/nope", json={})
        assert r.status_code == 404
        summary = (await c.get("/audit/summary")).json()
        assert summary["total"] == 2


async def test_fastapi_agent_with_human_approval(fastapi_example) -> None:  # type: ignore[no-untyped-def]
    transport = httpx.ASGITransport(app=fastapi_example)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=30) as c:
        run = asyncio.create_task(
            c.post("/agent/run", json={"agent_id": "ops-agent", "question": "clean up"})
        )

        async def next_pending() -> dict:
            for _ in range(500):
                pending = (await c.get("/approvals")).json()
                if pending:
                    return pending[0]
                await asyncio.sleep(0.01)
            raise AssertionError("no approval request appeared")

        first = await next_pending()
        assert first["tool"] == "delete_file"
        await c.post(f"/approvals/{first['id']}/approve", json={"approver": "alice"})
        second = await next_pending()
        assert second["tool"] == "run_sql" and "modifies data" in second["reason"]
        await c.post(
            f"/approvals/{second['id']}/deny", json={"approver": "alice", "comment": "not today"}
        )

        body = (await run).json()
        outputs = [r["output"] for r in body["tool_results"]]
        assert outputs[0].startswith("Refunds are issued")
        assert outputs[1] == "deleted docs/ops/keys.md"
        assert "denied_by_human" in outputs[2] and "not today" in outputs[2]


async def test_multi_tenant_example(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUDIT_TOKEN", "audit-secret")
    mod = load("multi_tenant")
    app = mod.create_app(audit_path=tmp_path / "t.db")
    acme, globex = {"x-tenant": "acme"}, {"x-tenant": "globex"}
    auth = {"authorization": "Bearer audit-secret"}
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post(
            "/agents/member/tools",
            json={"id": "c1", "name": "read_doc", "arguments": {"doc": "a"}},
            headers=acme,
        )
        assert r.json() == {"status": "ok", "result": "contents of a"}
        r = await c.post(
            "/agents/member/tools",
            json={"id": "c2", "name": "delete_doc", "arguments": {"doc": "a"}},
            headers=acme,
        )
        assert r.json()["status"] == "denied" and "Do not retry" in r.json()["message"]
        r = await c.post(
            "/agents/admin/tools",
            json={"id": "c3", "name": "delete_doc", "arguments": {"doc": "b"}},
            headers=globex,
        )
        assert r.json()["status"] == "paused"
        approval_id = r.json()["approval_id"]

        # A restart: a fresh gateway on the same file sees the pending request.
        from mcp_rbac_gateway import Sentinel

        other = Sentinel(app.state.gateway.config)
        assert [p.id for p in other.broker.pending("globex")] == [approval_id]
        assert other.broker.pending("acme") == []
        other.close()

        # Another tenant cannot decide it; the owner can, once.
        body = {"approved": True, "approver": "gina"}
        assert (
            await c.post(f"/approvals/{approval_id}", json=body, headers=acme)
        ).status_code == 404
        r = await c.post(f"/approvals/{approval_id}", json=body, headers=globex)
        assert r.json() == {"status": "ok", "result": "deleted b"}

        # Scoped audit: each tenant sees only its own rows, whatever it asks for.
        assert (await c.get("/audit", headers=acme)).status_code == 401
        rows = (await c.get("/audit?tenant_id=globex", headers={**acme, **auth})).json()["events"]
        assert {e["tenant_id"] for e in rows} == {"acme"}
        assert [e["request_id"] for e in rows] == ["c2", "c1"]
        rows = (await c.get("/audit", headers={**globex, **auth})).json()["events"]
        assert [e["decision"] for e in rows] == ["approved", "pending_approval"]
        assert rows[0]["approver"] == "gina" and rows[0]["approval_id"] == approval_id
    app.state.gateway.close()
