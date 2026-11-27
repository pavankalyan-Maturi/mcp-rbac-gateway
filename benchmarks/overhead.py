"""Per-call overhead of the gateway.

Run:  python benchmarks/overhead.py [--n 2000]

Measures, for an in-process ``Sentinel.call`` around a no-op tool:

* an allowed call, audit off
* an allowed call with a SQLite audit row, ``audit.writer: sync`` (the default)
* the same with ``audit.writer: batched``
* a call denied by policy, sync audit
* ``check_result`` (output scan) on a 2 kB tool result

Prints p50/p95/p99 in milliseconds. Numbers depend on the disk (each sync
row is a committed transaction, so an fsync) and the CPU; run it on the
machine you deploy to.
"""

from __future__ import annotations

import argparse
import asyncio
import platform
import statistics
import sys
import tempfile
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from mcp_rbac_gateway import AutoApprover, Sentinel, SentinelConfig, ToolBlockedError


def make(tmp: Path, audit: str | None) -> Sentinel:
    cfg: dict[str, Any] = {
        "agents": {"default": {"allow": ["*"], "deny": ["drop_*"]}},
        "scanner": {"scan_inputs_for_injection": True},
        "audit": {"enabled": audit is not None, "path": str(tmp / f"{audit}.db")},
    }
    if audit:
        cfg["audit"]["writer"] = audit
    return Sentinel(SentinelConfig.model_validate(cfg), approver=AutoApprover(True))


async def noop(_: dict[str, Any]) -> str:
    return "ok"


async def measure(n: int, fn: Callable[[], Awaitable[Any]]) -> list[float]:
    for _ in range(min(100, n)):  # warm up
        await fn()
    out = []
    for _ in range(n):
        start = time.perf_counter()
        await fn()
        out.append((time.perf_counter() - start) * 1000)
    return out


def row(name: str, samples: list[float]) -> str:
    q = statistics.quantiles(samples, n=100)
    return f"| {name:<38} | {q[49]:>7.3f} | {q[94]:>7.3f} | {q[98]:>7.3f} |"


async def main(n: int) -> None:
    args = {"path": "/srv/data/report.txt", "query": "select * from orders where id = 42"}
    text = ("Order 42 shipped to Jane at 221B Baker Street. " * 50)[:2048]
    results: list[tuple[str, list[float]]] = []
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        for label, audit in [
            ("allowed, audit off", None),
            ("allowed, SQLite audit (sync)", "sync"),
            ("allowed, SQLite audit (batched)", "batched"),
        ]:
            s = make(tmp, audit)
            results.append((label, await measure(n, lambda s=s: s.call("read_file", args, noop))))
            s.close()

        s = make(tmp, "sync")

        async def denied() -> None:
            try:
                await s.call("drop_table", args, noop)
            except ToolBlockedError:
                pass

        results.append(("denied by policy, SQLite audit (sync)", await measure(n, denied)))

        async def scan() -> None:
            s.check_result(text)

        results.append(("output scan, 2 kB result", await measure(n, scan)))
        s.close()

    print(f"python {platform.python_version()} on {platform.machine()}, n={n}\n")
    print("| case                                   |  p50 ms |  p95 ms |  p99 ms |")
    print("|----------------------------------------|---------|---------|---------|")
    for name, samples in results:
        print(row(name, samples))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--n", type=int, default=2000, help="calls per case")
    ns = parser.parse_args()
    sys.exit(asyncio.run(main(ns.n)))
