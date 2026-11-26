from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from mcp_sentinel import AuditLog, AutoApprover, Sentinel, SentinelConfig

HERE = Path(__file__).parent
MOCK_SERVER = [sys.executable, str(HERE / "mock_mcp_server.py")]

CONFIG_YAML = r"""
version: 1
default_agent: guest
default_action: deny
agents:
  guest:
    allow: ["read_*", "echo"]
  researcher:
    inherits: [guest]
    allow: ["fetch_page", "leak_secrets", "explode"]
    arguments:
      read_file:
        path:
          pattern: '/workspace/.*'
          deny_pattern: '\.\./'
  operator:
    inherits: [researcher]
    allow: ["*"]
    deny: ["drop_*"]
    require_approval: ["write_file"]
scanner:
  custom_patterns:
    - name: employee_id
      pattern: 'EMP-\d{6}'
  prompt_injection:
    action: block
    threshold: 0.7
hitl:
  mode: auto_approve
  timeout_seconds: 2
  rules:
    - tool: run_sql
      when: { query: '(?i)\bdrop\b' }
      reason: destructive SQL
audit:
  path: PLACEHOLDER
"""


@pytest.fixture
def config(tmp_path: Path) -> SentinelConfig:
    text = CONFIG_YAML.replace("PLACEHOLDER", str(tmp_path / "audit.db"))
    return SentinelConfig.from_yaml_string(text)


@pytest.fixture
def config_file(tmp_path: Path) -> Path:
    path = tmp_path / "sentinel.yaml"
    path.write_text(CONFIG_YAML.replace("PLACEHOLDER", str(tmp_path / "audit.db")))
    return path


@pytest.fixture
def approver() -> AutoApprover:
    return AutoApprover(True, approver="test-human")


@pytest.fixture
def sentinel(config: SentinelConfig, approver: AutoApprover) -> Iterator[Sentinel]:
    s = Sentinel(config, approver=approver)
    yield s
    s.close()


@pytest.fixture
def audit(sentinel: Sentinel) -> AuditLog:
    assert sentinel.audit is not None
    return sentinel.audit
