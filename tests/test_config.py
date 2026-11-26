from __future__ import annotations

import pytest
from pydantic import ValidationError

from mcp_rbac_gateway import SentinelConfig, load_config


def test_empty_config_is_valid() -> None:
    cfg = SentinelConfig.from_yaml_string("")
    assert cfg.default_action == "deny"
    assert cfg.hitl.mode == "cli"
    assert cfg.scanner.prompt_injection.action == "block"


def test_load_from_file(config_file) -> None:
    cfg = load_config(config_file)
    assert set(cfg.agents) == {"guest", "researcher", "operator"}
    assert cfg.agents["operator"].require_approval == ["write_file"]


def test_unknown_keys_are_rejected() -> None:
    with pytest.raises(ValidationError, match="alow"):
        SentinelConfig.from_yaml_string("agents:\n  a:\n    alow: ['*']\n")


def test_invalid_regex_is_rejected() -> None:
    bad = "agents:\n  a:\n    arguments:\n      t:\n        x: {pattern: '(['}\n"
    with pytest.raises(ValidationError, match="invalid regular expression"):
        SentinelConfig.from_yaml_string(bad)


def test_unknown_parent_is_rejected() -> None:
    with pytest.raises(ValidationError, match="unknown agent"):
        SentinelConfig.from_yaml_string("agents:\n  a:\n    inherits: [ghost]\n")


def test_inheritance_cycle_is_rejected() -> None:
    text = "agents:\n  a: {inherits: [b]}\n  b: {inherits: [c]}\n  c: {inherits: [a]}\n"
    with pytest.raises(ValidationError, match="cycle"):
        SentinelConfig.from_yaml_string(text)


def test_string_shorthands() -> None:
    cfg = SentinelConfig.from_yaml_string(
        "agents:\n  a: {allow: read_file}\nupstream:\n  command: python -m server --flag 'a b'\n"
    )
    assert cfg.agents["a"].allow == ["read_file"]
    assert cfg.upstream.command == ["python", "-m", "server", "--flag", "a b"]


def test_env_expansion(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOOK", "https://hooks.example/x")
    cfg = SentinelConfig.from_yaml_string(
        "hitl:\n  webhook:\n    url: ${HOOK}\n    callback_base_url: ${MISSING:-http://localhost}\n"
    )
    assert cfg.hitl.webhook.url == "https://hooks.example/x"
    assert cfg.hitl.webhook.callback_base_url == "http://localhost"


def test_non_mapping_rejected() -> None:
    with pytest.raises(ValueError, match="mapping"):
        SentinelConfig.from_yaml_string("- a\n- b\n")
