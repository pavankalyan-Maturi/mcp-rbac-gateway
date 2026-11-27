"""Sync API: call_sync, check_call_sync and @guard on plain functions."""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any

import pytest

from mcp_rbac_gateway import (
    ApprovalRequest,
    AuditDecision,
    AuditLog,
    CallbackApprover,
    Sentinel,
    SentinelConfig,
    ToolBlockedError,
    call_context,
)


def test_check_call_sync(sentinel: Sentinel) -> None:
    assert sentinel.check_call_sync("guest", "read_file", {"path": "/a"}).allowed
    assert not sentinel.check_call_sync("guest", "delete_file", {}).allowed


def test_call_sync_runs_fn_in_calling_thread(sentinel: Sentinel, audit: AuditLog) -> None:
    seen: list[int] = []

    def read(args: dict[str, Any]) -> str:
        seen.append(threading.get_ident())
        return f"read {args['path']}"

    assert sentinel.call_sync("read_file", {"path": "/a"}, read) == "read /a"
    assert seen == [threading.get_ident()]
    with pytest.raises(ToolBlockedError):
        sentinel.call_sync("delete_file", {"path": "/a"}, read)
    assert [e.decision for e in audit.query()] == [
        AuditDecision.BLOCKED_POLICY,
        AuditDecision.ALLOWED,
    ]


def test_guard_plain_function_from_plain_code(sentinel: Sentinel, audit: AuditLog) -> None:
    @sentinel.guard
    def read_file(path: str) -> str:
        return f"contents of {path}"

    with call_context(tenant_id="acme"):
        assert read_file("/workspace/a") == "contents of /workspace/a"
    [event] = audit.query()
    assert event.tool == "read_file" and event.tenant_id == "acme"


async def test_guard_plain_function_via_to_thread(sentinel: Sentinel, audit: AuditLog) -> None:
    @sentinel.guard
    def read_file(path: str) -> str:
        return f"contents of {path}"

    with call_context(request_id="c1"):
        out = await asyncio.to_thread(read_file, "/workspace/b")
    assert out == "contents of /workspace/b"
    assert audit.query()[0].request_id == "c1"


async def test_guard_plain_function_inside_running_loop(
    sentinel: Sentinel, audit: AuditLog
) -> None:
    # Called directly on the loop thread: the check runs in a worker thread
    # instead of a nested asyncio.run, which would raise.
    @sentinel.guard
    def read_file(path: str) -> str:
        return f"contents of {path}"

    with call_context(tenant_id="inside"):
        assert read_file("/workspace/c") == "contents of /workspace/c"
    assert audit.query()[0].tenant_id == "inside"


def test_sync_path_waits_for_approval(config: SentinelConfig) -> None:
    asked: list[ApprovalRequest] = []

    async def slow_human(request: ApprovalRequest) -> bool:
        asked.append(request)
        await asyncio.sleep(0.1)
        return True

    s = Sentinel(config, approver=CallbackApprover(slow_human, approver="alice"), audit=False)

    @s.guard(agent_id="operator")
    def write_file(path: str, content: str) -> str:
        return f"wrote {path}"

    started = time.perf_counter()
    assert write_file("/workspace/a", "x") == "wrote /workspace/a"
    assert time.perf_counter() - started >= 0.1
    assert asked and asked[0].tool == "write_file"
    s.close()
