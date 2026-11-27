"""Integration tests for the HTTP reverse proxy (Streamable HTTP + legacy SSE)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import httpx
import pytest

from mcp_rbac_gateway import HttpProxy, Sentinel, SentinelConfig

from .mock_http_server import create_app
from .servers import serve


@pytest.fixture
def upstream() -> Iterator[tuple[str, Any]]:
    app = create_app()
    with serve(app) as url:
        yield url, app


@pytest.fixture
def proxy_url(sentinel: Sentinel, upstream: tuple[str, Any]) -> Iterator[str]:
    url, _ = upstream
    proxy = HttpProxy(sentinel, f"{url}/mcp", default_agent="researcher")
    with serve(proxy.build_app()) as base:
        yield base


def rpc(method: str, params: dict[str, Any] | None = None, mid: int = 1) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}}


def call(name: str, mid: int = 1, **arguments: Any) -> dict[str, Any]:
    return rpc("tools/call", {"name": name, "arguments": arguments}, mid)


def sse_messages(text: str) -> list[dict[str, Any]]:
    return [json.loads(line[6:]) for line in text.splitlines() if line.startswith("data: ")]


def test_json_mode(proxy_url: str, upstream: tuple[str, Any]) -> None:
    _, app = upstream
    with httpx.Client(base_url=proxy_url) as c:
        r = c.post("/mcp", json=rpc("tools/list"))
        assert r.headers["mcp-session-id"] == "sess-123"
        names = {t["name"] for t in r.json()["result"]["tools"]}
        assert "delete_file" not in names and "read_file" in names

        r = c.post("/mcp", json=call("leak_secrets"))
        assert "AKIAIOSFODNN7EXAMPLE" not in r.text

        r = c.post("/mcp", json=call("delete_file", path="/x"))
        assert r.json()["result"]["isError"] is True
    assert [p["name"] for p in app.state.calls] == ["leak_secrets"]


def test_sse_mode(proxy_url: str) -> None:
    with httpx.Client(base_url=proxy_url) as c:
        r = c.post("/mcp", json=call("fetch_page"), headers={"x-mock-mode": "sse"})
        assert r.headers["content-type"].startswith("text/event-stream")
        [msg] = sse_messages(r.text)
        assert (
            msg["result"]["isError"] is True and "withheld" in msg["result"]["content"][0]["text"]
        )


def test_batch_with_mixed_outcomes(proxy_url: str) -> None:
    batch = [call("read_file", 1, path="/workspace/a"), call("delete_file", 2, path="/x")]
    with httpx.Client(base_url=proxy_url) as c:
        r = c.post("/mcp", json=batch)
    by_id = {m["id"]: m for m in r.json()}
    assert by_id[1]["result"]["content"][0]["text"] == "contents of /workspace/a"
    assert by_id[2]["result"]["isError"] is True


def test_notifications_return_202(proxy_url: str) -> None:
    with httpx.Client(base_url=proxy_url) as c:
        r = c.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert r.status_code == 202


def test_agent_header_selects_policy(proxy_url: str) -> None:
    with httpx.Client(base_url=proxy_url) as c:
        r = c.post("/mcp", json=call("fetch_page"), headers={"x-sentinel-agent": "guest"})
    assert "blocked_policy" in r.json()["result"]["content"][0]["text"]


def test_parse_error(proxy_url: str) -> None:
    with httpx.Client(base_url=proxy_url) as c:
        r = c.post("/mcp", content=b"{nope")
    assert r.status_code == 400 and r.json()["error"]["code"] == -32700


def test_token_auth(
    config: SentinelConfig, upstream: tuple[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OP_TOKEN", "op-secret")
    config.agents["operator"].token_env = "OP_TOKEN"
    s = Sentinel(config, audit=False)
    url, _ = upstream
    proxy = HttpProxy(s, f"{url}/mcp", default_agent="guest")
    with serve(proxy.build_app()) as base, httpx.Client(base_url=base) as c:
        # A spoofed agent header is ignored once tokens are configured.
        r = c.post("/mcp", json=call("fetch_page"), headers={"x-sentinel-agent": "operator"})
        assert "blocked_policy" in r.text
        r = c.post("/mcp", json=call("fetch_page"), headers={"x-sentinel-token": "wrong"})
        assert r.status_code == 401
        r = c.post("/mcp", json=call("fetch_page"), headers={"x-sentinel-token": "op-secret"})
        assert "withheld" in r.text  # allowed by policy, then caught by the scanner


def test_legacy_sse_transport(sentinel: Sentinel, upstream: tuple[str, Any]) -> None:
    url, app = upstream
    proxy = HttpProxy(sentinel, f"{url}/sse", default_agent="researcher")
    with serve(proxy.build_app()) as base, httpx.Client(base_url=base, timeout=10) as c:
        with c.stream("GET", "/sse") as stream:
            lines = stream.iter_lines()
            endpoint = None
            for line in lines:
                if line.startswith("data: "):
                    endpoint = line[6:]
                    break
            assert endpoint is not None and endpoint.startswith("/messages?session_id=")

            def next_message() -> dict[str, Any]:
                for line in lines:
                    if line.startswith("data: "):
                        return json.loads(line[6:])
                raise AssertionError("stream ended")

            assert c.post(endpoint, json=call("leak_secrets", 1)).status_code == 202
            msg = next_message()
            assert msg["id"] == 1 and "AKIAIOSFODNN7EXAMPLE" not in json.dumps(msg)

            assert c.post(endpoint, json=call("delete_file", 2, path="/x")).status_code == 202
            msg = next_message()
            assert msg["id"] == 2 and msg["result"]["isError"] is True

    assert [p["name"] for p in app.state.calls] == ["leak_secrets"]


def test_unknown_legacy_session(proxy_url: str) -> None:
    with httpx.Client(base_url=proxy_url) as c:
        assert c.post("/messages?session_id=nope", json=rpc("ping")).status_code == 404


def test_healthz_and_approvals(proxy_url: str) -> None:
    with httpx.Client(base_url=proxy_url) as c:
        assert c.get("/healthz").json() == {"status": "ok"}
        # 0.3.0: no approval_token, so /approvals is not mounted (it was open before).
        assert c.get("/approvals").status_code == 404
