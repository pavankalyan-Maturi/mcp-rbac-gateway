"""The optional batched audit writer (audit.writer: batched)."""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path

from mcp_rbac_gateway import (
    AuditDecision,
    AuditEvent,
    AuditLog,
    AutoApprover,
    Sentinel,
    SentinelConfig,
    call_context,
)
from mcp_rbac_gateway.config import AuditConfig


def batched(path: Path, **kw: object) -> AuditLog:
    cfg = AuditConfig.model_validate({"path": str(path), "writer": "batched", **kw})
    return AuditLog.from_config(cfg)


def event(i: int) -> AuditEvent:
    return AuditEvent(agent_id="a", tool=f"t{i}", decision=AuditDecision.ALLOWED, reason="ok")


def test_default_writer_is_sync(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "a.db")
    assert log.config.writer == "sync"
    assert log.record_sync(event(1)) == 1


def test_reads_flush_first(tmp_path: Path) -> None:
    log = batched(tmp_path / "a.db", flush_interval_ms=10_000, batch_size=1000)
    for i in range(25):
        assert log.record_sync(event(i)) == 0
    # The writer would wait 10 s for a full batch; a read must not.
    assert log.count() == 25
    assert [e.tool for e in log.query(limit=3)] == ["t24", "t23", "t22"]
    log.close()


def test_close_flushes_and_rows_survive(tmp_path: Path) -> None:
    path = tmp_path / "a.db"
    log = batched(path, flush_interval_ms=10_000, batch_size=1000)
    for i in range(10):
        log.record_sync(event(i))
    log.close()
    with AuditLog(path) as reopened:
        assert reopened.count() == 10


def test_bounded_queue_blocks_instead_of_dropping(tmp_path: Path) -> None:
    log = batched(tmp_path / "a.db", queue_size=2, batch_size=1, flush_interval_ms=1)
    threads = [
        threading.Thread(
            target=lambda n=n: [log.record_sync(event(n * 100 + i)) for i in range(50)]
        )
        for n in range(4)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert log.count() == 200
    log.close()


async def test_gateway_with_batched_writer(tmp_path: Path) -> None:
    cfg = SentinelConfig.model_validate(
        {
            "agents": {"default": {"allow": ["*"], "deny": ["rm"]}},
            "audit": {"path": str(tmp_path / "a.db"), "writer": "batched"},
        }
    )
    s = Sentinel(cfg, approver=AutoApprover(True))

    @s.guard(on_block="result")
    async def echo(text: str) -> str:
        return text

    @s.guard(on_block="result")
    async def rm(path: str) -> str:  # pragma: no cover - blocked
        return path

    with call_context(tenant_id="acme"):
        await asyncio.gather(*(echo(text=str(i)) for i in range(20)), rm(path="/"))
    assert s.audit is not None
    rows = s.audit.query(tenant_id="acme", limit=100)
    assert len(rows) == 21
    assert sum(r.decision is AuditDecision.BLOCKED_POLICY for r in rows) == 1
    s.close()
