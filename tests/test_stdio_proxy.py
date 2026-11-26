"""End-to-end tests: real `mcp-sentinel wrap` process in front of a mock MCP server."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from mcp_sentinel import AuditDecision, AuditLog

from .conftest import MOCK_SERVER
from .mcp_client import StdioClient, text_of


@pytest.fixture
def calls_log(tmp_path: Path) -> Path:
    return tmp_path / "upstream_calls.jsonl"


def upstream_calls(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


async def start(config_file: Path, calls_log: Path, agent: str) -> StdioClient:
    env = {**os.environ, "MOCK_MCP_LOG": str(calls_log)}
    return await StdioClient.spawn(
        sys.executable,
        "-m",
        "mcp_sentinel.cli",
        "wrap",
        "--config",
        str(config_file),
        "--agent",
        agent,
        "--",
        *MOCK_SERVER,
        env=env,
    )


@pytest.fixture
async def researcher(config_file: Path, calls_log: Path) -> AsyncIterator[StdioClient]:
    client = await start(config_file, calls_log, "researcher")
    await client.initialize()
    yield client
    await client.close()


async def test_initialize_passthrough(researcher: StdioClient) -> None:
    pong = await researcher.request("ping")
    assert pong["result"] == {}


async def test_tools_list_is_filtered_per_agent(researcher: StdioClient) -> None:
    resp = await researcher.request("tools/list")
    names = {t["name"] for t in resp["result"]["tools"]}
    assert names == {"read_file", "echo", "fetch_page", "leak_secrets", "explode"}


async def test_allowed_call_reaches_upstream(researcher: StdioClient, calls_log: Path) -> None:
    resp = await researcher.call_tool("read_file", path="/workspace/a.txt")
    assert text_of(resp) == "contents of /workspace/a.txt"
    assert upstream_calls(calls_log) == [
        {"tool": "read_file", "arguments": {"path": "/workspace/a.txt"}}
    ]


async def test_policy_block_never_reaches_upstream(
    researcher: StdioClient, calls_log: Path
) -> None:
    resp = await researcher.call_tool("delete_file", path="/workspace/a.txt")
    assert resp["result"]["isError"] is True
    assert "blocked_policy" in text_of(resp)
    resp = await researcher.call_tool("read_file", path="/workspace/../etc/passwd")
    assert "forbidden pattern" in text_of(resp)
    assert upstream_calls(calls_log) == []


async def test_secret_arguments_redacted_before_upstream(
    researcher: StdioClient, calls_log: Path
) -> None:
    await researcher.call_tool("echo", note="deploy with AKIAIOSFODNN7EXAMPLE")
    assert upstream_calls(calls_log)[0]["arguments"] == {
        "note": "deploy with [REDACTED:aws_access_key]"
    }


async def test_secret_outputs_redacted(researcher: StdioClient) -> None:
    out = text_of(await researcher.call_tool("leak_secrets"))
    for leaked in ("Sup3rS3cretPass!", "jane.doe@example.com", "AKIAIOSFODNN7EXAMPLE", "ghp_"):
        assert leaked not in out
    assert "[REDACTED:email]" in out


async def test_prompt_injection_withheld(researcher: StdioClient) -> None:
    resp = await researcher.call_tool("fetch_page", url="https://docs.example")
    assert resp["result"]["isError"] is True
    out = text_of(resp)
    assert "withheld" in out and "evil.example" not in out


async def test_upstream_error_passthrough(researcher: StdioClient) -> None:
    resp = await researcher.call_tool("explode")
    assert resp["error"]["message"] == "boom"


async def test_resources_are_redacted(researcher: StdioClient) -> None:
    resp = await researcher.request("resources/read", {"uri": "mem://secret"})
    assert resp["result"]["contents"][0]["text"] == "token=[REDACTED:generic_secret]"


async def test_concurrent_calls(researcher: StdioClient) -> None:
    import asyncio

    resps = await asyncio.gather(*(researcher.call_tool("echo", i=i) for i in range(20)))
    assert sorted(json.loads(text_of(r))["i"] for r in resps) == list(range(20))


async def test_approval_flow_for_operator(config_file: Path, calls_log: Path) -> None:
    client = await start(config_file, calls_log, "operator")
    await client.initialize()
    await client.request("tools/list")  # caches destructiveHint for delete_file
    resp = await client.call_tool("write_file", path="/workspace/x", content="hi")
    assert text_of(resp).startswith("wrote 2 bytes")
    resp = await client.call_tool("delete_file", path="/workspace/x")
    assert text_of(resp) == "deleted /workspace/x"
    assert await client.close() == 0


async def test_every_call_is_audited(config_file: Path, calls_log: Path, tmp_path: Path) -> None:
    client = await start(config_file, calls_log, "researcher")
    await client.initialize()
    await client.call_tool("read_file", path="/workspace/a")
    await client.call_tool("delete_file", path="/x")
    await client.call_tool("fetch_page")
    await client.call_tool("explode")
    await client.close()
    with AuditLog(tmp_path / "audit.db") as log:
        events = {e.tool: e for e in log.query()}
    assert events["read_file"].decision is AuditDecision.ALLOWED
    assert events["delete_file"].decision is AuditDecision.BLOCKED_POLICY
    assert events["fetch_page"].decision is AuditDecision.BLOCKED_INJECTION
    assert events["explode"].decision is AuditDecision.ERROR
    assert all(e.transport == "stdio" and e.agent_id == "researcher" for e in events.values())
    assert all(e.latency_ms is not None for e in events.values())


async def test_unknown_agent_gets_default_policy(config_file: Path, calls_log: Path) -> None:
    client = await start(config_file, calls_log, "mystery")
    await client.initialize()
    names = {t["name"] for t in (await client.request("tools/list"))["result"]["tools"]}
    assert names == {"read_file", "echo"}
    await client.close()
