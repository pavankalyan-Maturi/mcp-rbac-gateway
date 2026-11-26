from __future__ import annotations

import json
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from mcp_rbac_gateway import AuditDecision, AuditEvent, AuditLog, SentinelConfig, __version__
from mcp_rbac_gateway.cli import SAMPLE_CONFIG, app, parse_since

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0 and __version__ in result.output


def test_init_writes_valid_config(tmp_path: Path) -> None:
    target = tmp_path / "sentinel.yaml"
    result = runner.invoke(app, ["init", str(target)])
    assert result.exit_code == 0, result.output
    SentinelConfig.from_yaml_string(target.read_text())
    assert runner.invoke(app, ["init", str(target)]).exit_code == 1  # refuses to overwrite
    assert runner.invoke(app, ["init", str(target), "--force"]).exit_code == 0


def test_sample_config_is_valid() -> None:
    cfg = SentinelConfig.from_yaml_string(SAMPLE_CONFIG)
    assert "operator" in cfg.agents


def test_validate(config_file: Path) -> None:
    result = runner.invoke(app, ["validate", "-c", str(config_file)])
    assert result.exit_code == 0, result.output
    assert "researcher" in result.output and "valid" in result.output


def test_validate_reports_errors(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("agents:\n  a:\n    alow: ['*']\n")
    result = runner.invoke(app, ["validate", "-c", str(bad)])
    assert result.exit_code == 2
    assert runner.invoke(app, ["validate", "-c", str(tmp_path / "missing.yaml")]).exit_code == 2


def test_check(config_file: Path) -> None:
    ok = runner.invoke(
        app,
        [
            "check",
            "-c",
            str(config_file),
            "-a",
            "researcher",
            "read_file",
            '{"path": "/workspace/a"}',
        ],
    )
    assert ok.exit_code == 0 and "allow" in ok.output
    bad = runner.invoke(
        app,
        [
            "check",
            "-c",
            str(config_file),
            "-a",
            "researcher",
            "read_file",
            '{"path": "/etc/passwd"}',
        ],
    )
    assert bad.exit_code == 1 and "deny" in bad.output
    hitl = runner.invoke(
        app,
        [
            "check",
            "-c",
            str(config_file),
            "-a",
            "operator",
            "write_file",
            '{"path": "/workspace/a"}',
        ],
    )
    assert hitl.exit_code == 0 and "require_approval" in hitl.output


def seed(path: Path) -> None:
    with AuditLog(path) as log:
        log.record_sync(
            AuditEvent(
                agent_id="researcher",
                tool="read_file",
                decision=AuditDecision.ALLOWED,
                latency_ms=12.5,
            )
        )
        log.record_sync(
            AuditEvent(
                agent_id="researcher",
                tool="delete_file",
                decision=AuditDecision.BLOCKED_POLICY,
                reason="tool 'delete_file' [x]",
            )
        )
        log.record_sync(
            AuditEvent(
                agent_id="operator",
                tool="write_file",
                decision=AuditDecision.APPROVED,
                latency_ms=2500,
            )
        )


def test_report(tmp_path: Path) -> None:
    db = tmp_path / "audit.db"
    seed(db)
    result = runner.invoke(app, ["report", "--db", str(db), "--since", "all"])
    assert result.exit_code == 0, result.output
    for text in ("mcp-rbac-gateway report", "read_file", "blocked_policy", "operator", "[x]"):
        assert text in result.output


def test_report_json(tmp_path: Path) -> None:
    db = tmp_path / "audit.db"
    seed(db)
    result = runner.invoke(app, ["report", "--db", str(db), "--json", "--agent", "researcher"])
    data = json.loads(result.stdout)
    assert data["total"] == 2 and data["by_decision"]["blocked_policy"] == 1
    assert len(data["recent"]) == 2


def test_report_uses_config_audit_path(config_file: Path, tmp_path: Path) -> None:
    seed(tmp_path / "audit.db")
    result = runner.invoke(app, ["report", "-c", str(config_file)])
    assert result.exit_code == 0 and "read_file" in result.output


def test_report_missing_db(tmp_path: Path) -> None:
    assert runner.invoke(app, ["report", "--db", str(tmp_path / "none.db")]).exit_code == 1


def test_parse_since() -> None:
    import time

    assert parse_since("all") is None
    assert abs(parse_since("2h") - (time.time() - 7200)) < 5  # type: ignore[operator]
    with pytest.raises(typer.BadParameter):
        parse_since("yesterday")


def test_wrap_without_command(tmp_path: Path) -> None:
    cfg = tmp_path / "s.yaml"
    cfg.write_text("audit: {enabled: false}\n")
    result = runner.invoke(app, ["wrap", "-c", str(cfg)])
    assert result.exit_code == 2
