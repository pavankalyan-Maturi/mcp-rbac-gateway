"""Policy for non-tool methods and skills, and the audit schema upgrade."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from mcp_rbac_gateway import AuditLog, PolicyEngine, SentinelConfig
from mcp_rbac_gateway.mcp import (
    RequestMeta,
    decode_header_value,
    encode_header_value,
    param_header_map,
    skill_path,
)

CONFIG = """
default_action: deny
agents:
  base:
    methods: { deny: ["tasks/cancel"] }
    skills: { allow: ["acme/*"], deny: ["acme/secret"] }
  child:
    inherits: [base]
    methods: { allow: ["tasks/*", "skills/*"] }
  open:
    allow: ["*"]
"""


def engine() -> PolicyEngine:
    return PolicyEngine(SentinelConfig.from_yaml_string(CONFIG))


def test_methods_default_allow_and_deny_wins() -> None:
    e = engine()
    assert e.evaluate_method("open", "tasks/cancel").allowed
    assert not e.evaluate_method("base", "tasks/cancel").allowed
    assert e.evaluate_method("base", "skills/list").allowed
    # child has an allowlist: anything outside it is refused; inherited deny still wins.
    assert e.evaluate_method("child", "tasks/get").allowed
    assert not e.evaluate_method("child", "prompts/get").allowed
    assert not e.evaluate_method("child", "tasks/cancel").allowed


def test_skills_match_paths_and_parents() -> None:
    e = engine()
    assert e.evaluate_skill("base", "acme/pdf").allowed
    assert e.evaluate_skill("base", "acme/pdf/scripts/run.py").allowed
    assert not e.evaluate_skill("base", "acme/secret").allowed
    assert not e.evaluate_skill("base", "acme/secret/data.csv").allowed
    assert not e.evaluate_skill("base", "other/thing").allowed  # default_action: deny
    assert not e.evaluate_skill("open", "acme/pdf").allowed  # tool globs don't cover skills


def test_skill_path() -> None:
    assert skill_path("skill://acme/pdf/SKILL.md") == "acme/pdf"
    assert skill_path("skill://acme/pdf/scripts/x.py") == "acme/pdf/scripts/x.py"
    assert skill_path("file:///etc/passwd") is None


def test_header_value_encoding_round_trip() -> None:
    for value in ["get_weather", "héllo wörld", " padded ", "=?base64?abc?="]:
        assert decode_header_value(encode_header_value(value)) == value
    assert encode_header_value("get_weather") == "get_weather"
    assert encode_header_value("日本").startswith("=?base64?")


def test_param_header_map_follows_properties_only() -> None:
    schema = {
        "type": "object",
        "properties": {
            "region": {"type": "string", "x-mcp-header": "Region"},
            "opts": {"type": "object", "properties": {"tier": {"x-mcp-header": "Tier"}}},
        },
    }
    assert param_header_map(schema) == {
        "mcp-param-region": ("region",),
        "mcp-param-tier": ("opts", "tier"),
    }


def test_request_meta() -> None:
    meta = RequestMeta.from_params(
        {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "traceparent": "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01",
            }
        }
    )
    assert meta.is_stateless and meta.trace_id == "0af7651916cd43dd8448eb211c80319c"
    assert not RequestMeta.from_params({}).is_stateless


def test_old_audit_database_is_upgraded(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, "
        "agent_id TEXT NOT NULL, tool TEXT NOT NULL, decision TEXT NOT NULL, "
        "reason TEXT NOT NULL DEFAULT '', latency_ms REAL, transport TEXT NOT NULL DEFAULT "
        "'python', request_id TEXT, session_id TEXT, approver TEXT, arguments TEXT, "
        "result TEXT, findings TEXT, redactions INTEGER NOT NULL DEFAULT 0, "
        "injection_score REAL NOT NULL DEFAULT 0, is_error INTEGER NOT NULL DEFAULT 0)"
    )
    conn.execute(
        "INSERT INTO events (ts, agent_id, tool, decision) VALUES (1, 'a', 'echo', 'allowed')"
    )
    conn.commit()
    conn.close()
    with AuditLog(path) as log:
        [event] = log.query()
    assert event.method == "tools/call" and event.traceparent is None
