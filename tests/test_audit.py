from __future__ import annotations

import time
from pathlib import Path

from mcp_rbac_gateway import AuditDecision, AuditEvent, AuditLog, Finding
from mcp_rbac_gateway.config import AuditConfig


def ev(**kw: object) -> AuditEvent:
    base = {"agent_id": "a", "tool": "t", "decision": AuditDecision.ALLOWED, "latency_ms": 10.0}
    return AuditEvent.model_validate({**base, **kw})


async def test_record_and_query(tmp_path: Path) -> None:
    with AuditLog(tmp_path / "a.db") as log:
        await log.record(
            ev(arguments={"x": 1}, findings=[Finding(detector="email", kind="pii", path="$.x")])
        )
        await log.record(ev(agent_id="b", tool="rm", decision=AuditDecision.BLOCKED_POLICY))
        assert log.count() == 2
        rows = log.query()
        assert rows[0].tool == "rm"  # newest first
        assert rows[1].arguments == {"x": 1}
        assert rows[1].findings[0].detector == "email"
        assert [e.tool for e in log.query(blocked_only=True)] == ["rm"]
        assert [e.agent_id for e in log.query(agent_id="a")] == ["a"]
        assert log.query(decision="blocked_policy")[0].agent_id == "b"


def test_summary(tmp_path: Path) -> None:
    with AuditLog(tmp_path / "a.db") as log:
        for i in range(10):
            log.record_sync(ev(latency_ms=float(i + 1)))
        log.record_sync(ev(decision=AuditDecision.BLOCKED_INJECTION, injection_score=0.9))
        log.record_sync(ev(agent_id="b", tool="w", decision=AuditDecision.APPROVED))
        log.record_sync(ev(agent_id="b", tool="w", decision=AuditDecision.DENIED_BY_HUMAN))
        log.record_sync(ev(ts=time.time() - 7200, agent_id="old"))
        s = log.summary()
        assert s.total == 14
        assert s.by_decision["allowed"] == 11
        a = next(x for x in s.agents if x.agent_id == "a")
        assert (a.calls, a.blocked) == (11, 1)
        b = next(x for x in s.agents if x.agent_id == "b")
        assert (b.calls, b.blocked, b.approvals) == (2, 1, 1)
        t = next(x for x in s.tools if x.tool == "t")
        assert t.p95_latency_ms is not None and t.avg_latency_ms is not None
        assert s.injections == 1
        recent = log.summary(since=time.time() - 3600)
        assert recent.total == 13


def test_payloads_are_truncated_and_results_opt_in(tmp_path: Path) -> None:
    cfg = AuditConfig(path=str(tmp_path / "a.db"), max_payload_chars=20)
    with AuditLog(cfg.path, cfg) as log:
        log.record_sync(ev(arguments={"blob": "x" * 100}, result={"r": 1}))
        row = log.query()[0]
        assert isinstance(row.arguments, str) and "chars)" in row.arguments
        assert row.result is None  # log_results defaults to False


def test_wal_allows_concurrent_reader(tmp_path: Path) -> None:
    path = tmp_path / "a.db"
    writer = AuditLog(path)
    reader = AuditLog(path)
    writer.record_sync(ev())
    assert reader.count() == 1
    writer.close()
    reader.close()
