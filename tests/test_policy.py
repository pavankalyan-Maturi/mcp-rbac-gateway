from __future__ import annotations

import pytest

from mcp_sentinel import PolicyAction, PolicyEngine, SentinelConfig


@pytest.fixture
def engine(config: SentinelConfig) -> PolicyEngine:
    return PolicyEngine(config)


def test_allowlisted_tool(engine: PolicyEngine) -> None:
    d = engine.evaluate("guest", "read_file", {"path": "/tmp/x"})
    assert d.action is PolicyAction.ALLOW
    assert d.rule == "agents.guest.allow[read_*]"


def test_default_deny(engine: PolicyEngine) -> None:
    d = engine.evaluate("guest", "delete_file", {})
    assert d.action is PolicyAction.DENY
    assert "not in the allowlist" in d.reason


def test_unknown_agent_falls_back_to_default_agent(engine: PolicyEngine) -> None:
    assert engine.resolve_agent("who-knows") == "guest"
    assert engine.evaluate("who-knows", "read_file").allowed
    assert not engine.evaluate("who-knows", "fetch_page").allowed
    assert not engine.evaluate(None, "fetch_page").allowed


def test_inheritance(engine: PolicyEngine) -> None:
    # researcher inherits guest's read_* and adds fetch_page
    assert engine.evaluate("researcher", "fetch_page").allowed
    assert engine.evaluate("researcher", "echo").allowed
    assert not engine.evaluate("researcher", "write_file").allowed


def test_deny_beats_allow(engine: PolicyEngine) -> None:
    d = engine.evaluate("operator", "drop_database")
    assert d.action is PolicyAction.DENY
    assert d.rule == "agents.operator.deny[drop_*]"


def test_require_approval(engine: PolicyEngine) -> None:
    d = engine.evaluate("operator", "write_file", {"path": "/workspace/a"})
    assert d.action is PolicyAction.REQUIRE_APPROVAL
    assert d.allowed  # allowed, pending a human


@pytest.mark.parametrize(
    ("path", "allowed"),
    [
        ("/workspace/notes.md", True),
        ("/etc/passwd", False),
        ("/workspace/../etc/passwd", False),
    ],
)
def test_argument_regex(engine: PolicyEngine, path: str, allowed: bool) -> None:
    assert engine.evaluate("researcher", "read_file", {"path": path}).allowed is allowed


def test_argument_constraints_are_inherited(engine: PolicyEngine) -> None:
    # operator inherits researcher's path constraint
    assert not engine.evaluate("operator", "read_file", {"path": "/etc/shadow"}).allowed


def test_constraint_kinds() -> None:
    cfg = SentinelConfig.from_yaml_string(
        """
agents:
  default:
    allow: ["*"]
    arguments:
      "send_*":
        to: {required: true, pattern: '.+@acme\\.com'}
        priority: {allowed_values: [low, normal]}
        body: {max_length: 10}
"""
    )
    e = PolicyEngine(cfg)
    ok = {"to": "a@acme.com", "priority": "low", "body": "hi"}
    assert e.evaluate("default", "send_email", ok).allowed
    assert not e.evaluate("default", "send_email", {**ok, "to": "a@evil.com"}).allowed
    assert not e.evaluate("default", "send_email", {"priority": "low"}).allowed
    assert not e.evaluate("default", "send_email", {**ok, "priority": "urgent"}).allowed
    assert not e.evaluate("default", "send_email", {**ok, "body": "x" * 11}).allowed
    assert e.evaluate("default", "other_tool", {}).allowed


def test_non_string_arguments_are_matched_as_json() -> None:
    cfg = SentinelConfig.from_yaml_string(
        "agents:\n  default:\n    allow: ['*']\n    arguments:\n"
        "      t: {n: {pattern: '[0-9]{1,2}'}, flag: {pattern: 'false'}}\n"
    )
    e = PolicyEngine(cfg)
    assert e.evaluate("default", "t", {"n": 42, "flag": False}).allowed
    assert not e.evaluate("default", "t", {"n": 420}).allowed
    assert not e.evaluate("default", "t", {"flag": True}).allowed


def test_default_allow_mode() -> None:
    cfg = SentinelConfig.from_yaml_string(
        "default_action: allow\nagents:\n  default: {deny: ['rm_*']}\n"
    )
    e = PolicyEngine(cfg)
    assert e.evaluate("default", "anything").allowed
    assert not e.evaluate("default", "rm_rf").allowed


def test_filter_tools(engine: PolicyEngine) -> None:
    tools = [{"name": n} for n in ("read_file", "write_file", "echo", "drop_db")]
    assert [t["name"] for t in engine.filter_tools("guest", tools)] == ["read_file", "echo"]
    names = [t["name"] for t in engine.filter_tools("operator", tools)]
    assert names == ["read_file", "write_file", "echo"]
