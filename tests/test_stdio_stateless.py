"""stdio proxy with 2026-07-28 messages: _meta preservation, tasks and skills."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from mcp_rbac_gateway import AuditLog

from .conftest import MOCK_SERVER
from .mcp_client import StdioClient, text_of

TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientInfo": {"name": "StdioClient", "version": "9.9"},
    "io.modelcontextprotocol/clientCapabilities": {},
    "traceparent": TRACEPARENT,
    "baggage": "tenant=acme",
}


@pytest.fixture
async def operator(config_file: Path, tmp_path: Path) -> AsyncIterator[StdioClient]:
    env = {**os.environ, "MOCK_MCP_LOG": str(tmp_path / "calls.jsonl")}
    client = await StdioClient.spawn(
        sys.executable,
        "-m",
        "mcp_rbac_gateway.cli",
        "wrap",
        "--config",
        str(config_file),
        "--agent",
        "operator",
        "--",
        *MOCK_SERVER,
        env=env,
    )
    yield client  # no initialize: 2026-07-28 clients don't send one
    await client.close()


def audit_for(config_file: Path) -> AuditLog:
    return AuditLog(config_file.parent / "audit.db")


async def test_meta_preserved_and_audited(operator: StdioClient, config_file: Path) -> None:
    resp = await operator.request("tools/call", {"name": "echo_meta", "_meta": META})
    assert json.loads(text_of(resp)) == META
    with audit_for(config_file) as log:
        [event] = log.query()
    assert event.transport == "stdio" and event.method == "tools/call"
    assert event.client_name == "StdioClient" and event.client_version == "9.9"
    assert event.traceparent == TRACEPARENT
    assert event.meta is not None and event.meta["baggage"] == "tenant=acme"


async def test_task_over_stdio(operator: StdioClient, config_file: Path) -> None:
    handle = await operator.request("tools/call", {"name": "slow_job", "_meta": META})
    assert handle["result"]["resultType"] == "task"
    task = await operator.request("tasks/get", {"taskId": "task-1", "_meta": META})
    assert task["result"]["status"] == "completed"
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(task)
    unknown = await operator.request("tasks/get", {"taskId": "nope", "_meta": META})
    assert unknown["error"]["code"] == -32602
    with audit_for(config_file) as log:
        events = log.query(method="tasks/get")
    assert {(e.tool, e.decision.value) for e in events} == {
        ("slow_job", "allowed"),
        ("task:nope", "blocked_policy"),
    }


async def test_skills_follow_default_action(operator: StdioClient) -> None:
    # The shared test config has no `skills` rules and default_action: deny.
    listed = await operator.request("skills/list", {"_meta": META})
    assert listed["result"]["skills"] == []
    read = await operator.request("resources/read", {"uri": "skill://pdf/SKILL.md"})
    assert read["error"]["code"] == -32010


async def test_2025_11_25_task_result_is_scanned(operator: StdioClient, config_file: Path) -> None:
    created = await operator.request("tools/call", {"name": "legacy_job"})
    assert created["result"]["task"]["taskId"] == "t-old"
    resp = await operator.request("tasks/result", {"taskId": "t-old"})
    assert resp["result"]["isError"] is True and "withheld" in text_of(resp)
    with audit_for(config_file) as log:
        [event] = log.query(method="tasks/result")
    assert event.tool == "legacy_job" and event.decision.value == "blocked_injection"
