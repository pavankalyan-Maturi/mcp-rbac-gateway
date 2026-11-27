"""Stateless Streamable HTTP proxying (MCP 2026-07-28): headers, _meta, tasks and skills."""

from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from mcp_rbac_gateway import AuditLog, AutoApprover, Sentinel, SentinelConfig, StatelessHttpProxy
from mcp_rbac_gateway.mcp import LATEST_PROTOCOL_VERSION, NAME_SOURCES

from .mock_stateless_server import create_app
from .servers import serve

CONFIG = r"""
default_agent: guest
default_action: deny
agents:
  guest:
    allow: ["echo", "echo_meta", "slow_*", "set_note"]
    skills:
      allow: ["pdf", "evil"]
  intruder:
    allow: ["slow_*"]
  restricted:
    allow: ["echo"]
    methods:
      allow: ["tools/*"]
scanner:
  prompt_injection: { action: block, threshold: 0.7 }
hitl: { mode: auto_approve }
audit:
  path: PLACEHOLDER
"""

TRACEPARENT = "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01"
META = {
    "io.modelcontextprotocol/protocolVersion": LATEST_PROTOCOL_VERSION,
    "io.modelcontextprotocol/clientInfo": {"name": "ExampleClient", "version": "1.2.3"},
    "io.modelcontextprotocol/clientCapabilities": {
        "extensions": {"io.modelcontextprotocol/tasks": {}}
    },
    "traceparent": TRACEPARENT,
    "tracestate": "vendor=abc",
    "com.example/custom": {"keep": "me"},
}


@pytest.fixture
def sentinel(tmp_path: Path) -> Iterator[Sentinel]:
    cfg = SentinelConfig.from_yaml_string(CONFIG.replace("PLACEHOLDER", str(tmp_path / "a.db")))
    s = Sentinel(cfg, approver=AutoApprover(True))
    yield s
    s.close()


@pytest.fixture
def upstream() -> Iterator[tuple[str, Any]]:
    app = create_app()
    with serve(app) as url:
        yield url, app


@pytest.fixture
def proxy_url(sentinel: Sentinel, upstream: tuple[str, Any]) -> Iterator[str]:
    url, _ = upstream
    proxy = StatelessHttpProxy(sentinel, f"{url}/mcp")
    with serve(proxy.build_app()) as base:
        yield base


def message(method: str, params: dict[str, Any] | None = None, mid: int | None = 1) -> dict:
    body: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "params": params or {}}
    body["params"].setdefault("_meta", META)
    if mid is not None:
        body["id"] = mid
    return body


def headers_for(body: dict[str, Any], **extra: str) -> dict[str, str]:
    out = {
        "MCP-Protocol-Version": LATEST_PROTOCOL_VERSION,
        "Mcp-Method": body["method"],
        "Accept": "application/json, text/event-stream",
    }
    source = NAME_SOURCES.get(body["method"])
    if source:
        out["Mcp-Name"] = body["params"][source]
    out.update(extra)
    return out


def post(
    client: httpx.Client, body: dict[str, Any], agent: str | None = None, **extra: str
) -> httpx.Response:
    headers = headers_for(body, **extra)
    if agent:
        headers["X-Sentinel-Agent"] = agent
    return client.post("/mcp", json=body, headers=headers)


def call(name: str, mid: int = 1, **arguments: Any) -> dict[str, Any]:
    return message("tools/call", {"name": name, "arguments": arguments}, mid)


def received(upstream: tuple[str, Any]) -> list[tuple[dict[str, str], dict[str, Any]]]:
    return upstream[1].state.received  # type: ignore[no-any-return]


def audit_of(sentinel: Sentinel) -> AuditLog:
    assert sentinel.audit is not None
    return sentinel.audit


# ------------------------------------------------------------ plain requests


def test_request_without_initialize_or_session(
    proxy_url: str, upstream: tuple[str, Any], sentinel: Sentinel
) -> None:
    with httpx.Client(base_url=proxy_url) as c:
        r = post(c, call("echo_meta"), **{"Mcp-Session-Id": "stale-session"})
    assert r.status_code == 200
    assert "mcp-session-id" not in r.headers
    # _meta reached the server unchanged, custom keys included.
    assert json.loads(r.json()["result"]["content"][0]["text"]) == META
    [(headers, body)] = received(upstream)
    assert "mcp-session-id" not in headers
    assert headers["mcp-method"] == "tools/call" and headers["mcp-name"] == "echo_meta"
    assert body["params"]["_meta"] == META


def test_meta_is_audited(proxy_url: str, sentinel: Sentinel) -> None:
    with httpx.Client(base_url=proxy_url) as c:
        post(c, call("echo_meta"))
    [event] = audit_of(sentinel).query()
    assert event.method == "tools/call" and event.tool == "echo_meta"
    assert event.transport == "http-stateless" and event.session_id is None
    assert event.protocol_version == LATEST_PROTOCOL_VERSION
    assert (event.client_name, event.client_version) == ("ExampleClient", "1.2.3")
    assert event.traceparent == TRACEPARENT and event.tracestate == "vendor=abc"
    assert event.meta is not None and event.meta["com.example/custom"] == {"keep": "me"}
    by_trace = audit_of(sentinel).query(trace_id="0af7651916cd43dd8448eb211c80319c")
    assert [e.id for e in by_trace] == [event.id]


def test_blocked_call_never_reaches_upstream(
    proxy_url: str, upstream: tuple[str, Any], sentinel: Sentinel
) -> None:
    with httpx.Client(base_url=proxy_url) as c:
        r = post(c, call("delete_file", path="/x"))
    assert r.status_code == 200
    result = r.json()["result"]
    assert result["isError"] is True and result["resultType"] == "complete"
    assert received(upstream) == []
    [event] = audit_of(sentinel).query()
    assert event.decision.value == "blocked_policy" and event.traceparent == TRACEPARENT


def test_notification_is_forwarded(proxy_url: str, upstream: tuple[str, Any]) -> None:
    body = message("notifications/cancelled", {"requestId": 7}, mid=None)
    with httpx.Client(base_url=proxy_url) as c:
        r = post(c, body)
    assert r.status_code == 202
    assert received(upstream)[0][1]["method"] == "notifications/cancelled"


def test_sse_response_is_filtered(proxy_url: str) -> None:
    with httpx.Client(base_url=proxy_url) as c:
        r = post(c, call("slow_job"), **{"x-mock-mode": "sse"})
    assert r.headers["content-type"].startswith("text/event-stream")
    events = [json.loads(line[6:]) for line in r.text.splitlines() if line.startswith("data: ")]
    assert events[0]["method"] == "notifications/progress"
    assert events[1]["result"]["resultType"] == "task"


# ------------------------------------------------------------- header checks


def test_missing_protocol_version_header(proxy_url: str, upstream: tuple[str, Any]) -> None:
    body = call("echo")
    headers = headers_for(body)
    del headers["MCP-Protocol-Version"]
    with httpx.Client(base_url=proxy_url) as c:
        r = c.post("/mcp", json=body, headers=headers)
    assert r.status_code == 400
    error = r.json()["error"]
    assert error["code"] == -32022 and error["data"]["supported"] == [LATEST_PROTOCOL_VERSION]
    assert received(upstream) == []


def test_old_protocol_version_is_rejected(proxy_url: str) -> None:
    with httpx.Client(base_url=proxy_url) as c:
        r = post(c, call("echo"), **{"MCP-Protocol-Version": "2025-06-18"})
    assert r.status_code == 400 and r.json()["error"]["code"] == -32022


def test_meta_version_must_match_header(proxy_url: str) -> None:
    body = call("echo")
    body["params"]["_meta"] = {**META, "io.modelcontextprotocol/protocolVersion": "2025-11-25"}
    with httpx.Client(base_url=proxy_url) as c:
        r = post(c, body)
    assert r.status_code == 400 and r.json()["error"]["code"] == -32020


def test_meta_version_is_required(proxy_url: str) -> None:
    body = call("echo")
    body["params"]["_meta"] = {}
    with httpx.Client(base_url=proxy_url) as c:
        r = post(c, body)
    assert r.status_code == 400 and r.json()["error"]["code"] == -32602


def test_method_header_must_match_body(proxy_url: str, upstream: tuple[str, Any]) -> None:
    with httpx.Client(base_url=proxy_url) as c:
        r = post(c, call("echo"), **{"Mcp-Method": "tools/list"})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == -32020
    assert "Mcp-Method" in r.json()["error"]["message"]
    assert received(upstream) == []


def test_name_header_cannot_smuggle_a_different_tool(
    proxy_url: str, upstream: tuple[str, Any]
) -> None:
    # A router that trusts Mcp-Name would think this is the harmless `echo`.
    with httpx.Client(base_url=proxy_url) as c:
        r = post(c, call("delete_file", path="/etc"), **{"Mcp-Name": "echo"})
    assert r.status_code == 400 and r.json()["error"]["code"] == -32020
    assert received(upstream) == []


def test_name_header_is_required(proxy_url: str) -> None:
    body = call("echo")
    headers = headers_for(body)
    del headers["Mcp-Name"]
    with httpx.Client(base_url=proxy_url) as c:
        r = c.post("/mcp", json=body, headers=headers)
    assert r.status_code == 400 and r.json()["error"]["code"] == -32020


def test_base64_name_header(proxy_url: str) -> None:
    encoded = "=?base64?" + base64.b64encode(b"echo").decode() + "?="
    with httpx.Client(base_url=proxy_url) as c:
        r = post(c, call("echo", x=1), **{"Mcp-Name": encoded})
    assert r.status_code == 200 and r.json()["result"]["content"][0]["text"] == '{"x": 1}'


def test_batches_and_responses_are_rejected(proxy_url: str) -> None:
    with httpx.Client(base_url=proxy_url) as c:
        r = c.post("/mcp", json=[call("echo")], headers=headers_for(call("echo")))
        assert r.status_code == 400 and r.json()["error"]["code"] == -32600
        r = c.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "result": {}})
        assert r.status_code == 400


def test_get_and_delete_are_not_allowed(proxy_url: str) -> None:
    with httpx.Client(base_url=proxy_url) as c:
        assert c.get("/mcp").status_code == 405
        assert c.delete("/mcp").status_code == 405


def test_param_headers_follow_redacted_arguments(proxy_url: str, upstream: tuple[str, Any]) -> None:
    secret = "token=sk_live_abcdefghijklmnop1234"
    with httpx.Client(base_url=proxy_url) as c:
        post(c, message("tools/list"))  # the proxy learns x-mcp-header from inputSchema
        r = post(c, call("set_note", 2, note=secret), **{"Mcp-Param-Note": secret})
    assert r.status_code == 200, r.text
    headers, body = received(upstream)[-1]
    note = body["params"]["arguments"]["note"]
    assert "sk_live" not in note and "[REDACTED" in note
    assert headers["mcp-param-note"] == note


# ---------------------------------------------------------------------- tasks


def test_task_lifecycle(proxy_url: str, sentinel: Sentinel) -> None:
    with httpx.Client(base_url=proxy_url) as c:
        handle = post(c, call("slow_job")).json()["result"]
        assert handle["resultType"] == "task" and handle["taskId"] == "task-1"
        r = post(c, message("tasks/get", {"taskId": "task-1"}, 2))
    task = r.json()["result"]
    assert task["status"] == "completed"
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(task)
    events = audit_of(sentinel).query(method="tasks/get")
    assert [(e.tool, e.agent_id) for e in events] == [("slow_job", "guest")]
    assert events[0].redactions >= 1 and events[0].traceparent == TRACEPARENT


def test_other_agent_cannot_touch_a_task(proxy_url: str, upstream: tuple[str, Any]) -> None:
    with httpx.Client(base_url=proxy_url) as c:
        post(c, call("slow_job"))
        before = len(received(upstream))
        r = post(c, message("tasks/cancel", {"taskId": "task-1"}, 2), agent="intruder")
        assert r.json()["error"]["code"] == -32602
        r = post(c, message("tasks/get", {"taskId": "made-up"}, 3))
        assert r.json()["error"]["code"] == -32602
    assert len(received(upstream)) == before


def test_poisoned_task_result_is_withheld(proxy_url: str, sentinel: Sentinel) -> None:
    with httpx.Client(base_url=proxy_url) as c:
        post(c, call("slow_poison"))
        task = post(c, message("tasks/get", {"taskId": "task-p"}, 2)).json()["result"]
    assert task["result"]["isError"] is True
    assert "ignore all previous instructions" not in json.dumps(task)
    [event] = audit_of(sentinel).query(method="tasks/get")
    assert event.decision.value == "blocked_injection" and event.tool == "slow_poison"


def test_task_update_input_is_redacted(proxy_url: str, upstream: tuple[str, Any]) -> None:
    responses = {"key": {"action": "accept", "content": {"input": "my password=hunter2hunter2"}}}
    with httpx.Client(base_url=proxy_url) as c:
        post(c, call("slow_job"))
        r = post(c, message("tasks/update", {"taskId": "task-1", "inputResponses": responses}, 2))
    assert r.json()["result"] == {"resultType": "complete"}
    forwarded = received(upstream)[-1][1]["params"]["inputResponses"]
    assert "hunter2" not in json.dumps(forwarded)
    assert forwarded["key"]["action"] == "accept"


def test_task_name_header_is_the_task_id(proxy_url: str) -> None:
    with httpx.Client(base_url=proxy_url) as c:
        post(c, call("slow_job"))
        r = post(c, message("tasks/get", {"taskId": "task-1"}, 2), **{"Mcp-Name": "slow_job"})
    assert r.status_code == 400 and r.json()["error"]["code"] == -32020


# --------------------------------------------------------------------- skills


def test_skills_list_is_filtered(proxy_url: str) -> None:
    with httpx.Client(base_url=proxy_url) as c:
        skills = post(c, message("skills/list")).json()["result"]["skills"]
    assert {s["uri"] for s in skills} == {"skill://pdf/SKILL.md", "skill://evil/SKILL.md"}


def test_denied_skill_cannot_be_read(proxy_url: str, upstream: tuple[str, Any]) -> None:
    uri = "skill://internal/hr/SKILL.md"
    with httpx.Client(base_url=proxy_url) as c:
        r1 = post(c, message("skills/get", {"uri": uri}))
        r2 = post(c, message("resources/read", {"uri": uri}, 2))
    assert r1.json()["error"]["code"] == -32010
    assert r2.json()["error"]["code"] == -32010
    assert received(upstream) == []


def test_skill_content_is_scanned(proxy_url: str, sentinel: Sentinel) -> None:
    with httpx.Client(base_url=proxy_url) as c:
        ok = post(c, message("resources/read", {"uri": "skill://pdf/SKILL.md"}))
        bad = post(c, message("resources/read", {"uri": "skill://evil/SKILL.md"}, 2))
    assert "pdftotext" in ok.json()["result"]["contents"][0]["text"]
    assert bad.json()["error"]["code"] == -32010
    assert "withheld" in bad.json()["error"]["message"]
    decisions = {e.tool: e.decision.value for e in audit_of(sentinel).query()}
    assert decisions == {"skill:pdf": "allowed", "skill:evil": "blocked_injection"}


def test_methods_allowlist(proxy_url: str, upstream: tuple[str, Any]) -> None:
    with httpx.Client(base_url=proxy_url) as c:
        r = post(c, message("skills/list"), agent="restricted")
        assert r.json()["error"]["code"] == -32010
        assert "methods allowlist" in r.json()["error"]["message"]
        r = post(c, message("tools/list", mid=2), agent="restricted")
        assert [t["name"] for t in r.json()["result"]["tools"]] == ["echo"]
    assert [m["method"] for _, m in received(upstream)] == ["tools/list"]
