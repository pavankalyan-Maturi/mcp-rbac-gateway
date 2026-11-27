"""Typed configuration models for ``sentinel.yaml``.

Every section is optional, so the smallest valid config is an empty file.
Unknown keys are rejected so that typos (``alow:`` instead of ``allow:``)
fail loudly instead of silently weakening a policy.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

__all__ = [
    "ArgumentConstraint",
    "AgentPolicy",
    "ApprovalRule",
    "AuditConfig",
    "CustomPattern",
    "HitlConfig",
    "InjectionConfig",
    "NameRules",
    "ScannerConfig",
    "SentinelConfig",
    "TasksConfig",
    "UpstreamConfig",
    "WebhookConfig",
    "load_config",
]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=False)


def _check_regex(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        re.compile(value)
    except re.error as exc:  # pragma: no cover - message path tested via ValueError
        raise ValueError(f"invalid regular expression {value!r}: {exc}") from exc
    return value


class ArgumentConstraint(_Strict):
    """Constraints applied to a single tool argument.

    ``pattern`` must match (``re.fullmatch``) for the call to be allowed;
    ``deny_pattern`` must *not* match anywhere (``re.search``).
    """

    pattern: str | None = Field(default=None, description="Regex the value must fully match.")
    deny_pattern: str | None = Field(default=None, description="Regex that must not appear.")
    max_length: int | None = Field(default=None, ge=0)
    required: bool = False
    allowed_values: list[Any] | None = None

    _check = field_validator("pattern", "deny_pattern")(_check_regex)


class NameRules(_Strict):
    """Allow/deny globs for something other than tool names (methods, skills)."""

    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)

    @field_validator("allow", "deny", mode="before")
    @classmethod
    def _coerce_list(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [value]
        return value


class AgentPolicy(_Strict):
    """RBAC policy for one agent identity."""

    description: str = ""
    inherits: list[str] = Field(default_factory=list, description="Agents to inherit rules from.")
    allow: list[str] = Field(default_factory=list, description="Glob patterns of allowed tools.")
    deny: list[str] = Field(default_factory=list, description="Glob patterns of denied tools.")
    require_approval: list[str] = Field(
        default_factory=list, description="Glob patterns of tools that need human approval."
    )
    arguments: dict[str, dict[str, ArgumentConstraint]] = Field(
        default_factory=dict,
        description="Map of tool glob -> argument name -> constraint.",
    )
    methods: NameRules = Field(
        default_factory=NameRules,
        description="Globs of JSON-RPC methods other than tools/call (e.g. 'tasks/*', "
        "'skills/get'). Deny wins; a method no rule mentions is allowed.",
    )
    skills: NameRules = Field(
        default_factory=NameRules,
        description="Globs of skill paths (skill://<path>/SKILL.md). A skill no rule "
        "mentions follows default_action.",
    )
    token_env: str | None = Field(
        default=None,
        description="Environment variable holding this agent's bearer token (HTTP proxy only).",
    )

    @field_validator("inherits", "allow", "deny", "require_approval", mode="before")
    @classmethod
    def _coerce_list(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [value]
        return value


class CustomPattern(_Strict):
    name: str
    pattern: str
    replacement: str | None = None

    _check = field_validator("pattern")(_check_regex)


class InjectionConfig(_Strict):
    enabled: bool = True
    action: Literal["warn", "block"] = "block"
    threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    extra_patterns: list[CustomPattern] = Field(default_factory=list)


DEFAULT_INPUT_DETECTORS: tuple[str, ...] = (
    "private_key",
    "aws_access_key",
    "aws_secret_key",
    "github_token",
    "slack_token",
    "stripe_key",
    "openai_key",
    "anthropic_key",
    "google_api_key",
    "jwt",
    "bearer_token",
    "generic_secret",
)


class ScannerConfig(_Strict):
    enabled: bool = True
    redact_inputs: bool = True
    redact_outputs: bool = True
    input_detectors: list[str] | None = Field(
        default=None,
        description="Detectors applied to tool arguments. Default: secrets only (no PII), "
        "so that legitimate arguments like an email recipient are not mangled.",
    )
    output_detectors: list[str] | None = Field(
        default=None, description="Detectors applied to tool results. Default: all built-ins."
    )
    custom_patterns: list[CustomPattern] = Field(default_factory=list)
    prompt_injection: InjectionConfig = Field(default_factory=InjectionConfig)
    scan_inputs_for_injection: bool = False
    strip_invisible: bool = Field(
        default=True, description="Strip zero-width and Unicode tag characters from tool results."
    )

    def resolved_input_detectors(self) -> list[str]:
        if self.input_detectors is not None:
            return list(self.input_detectors)
        return list(DEFAULT_INPUT_DETECTORS)


class ApprovalRule(_Strict):
    """Require approval when a tool matches *and* its arguments match ``when``."""

    tool: str = "*"
    when: dict[str, str] = Field(
        default_factory=dict, description="Argument name -> regex (re.search)."
    )
    reason: str | None = None

    @field_validator("when")
    @classmethod
    def _check_when(cls, value: dict[str, str]) -> dict[str, str]:
        for regex in value.values():
            _check_regex(regex)
        return value


class WebhookConfig(_Strict):
    url: str | None = Field(default=None, description="Where approval requests are POSTed.")
    headers: dict[str, str] = Field(default_factory=dict)
    callback_base_url: str | None = Field(
        default=None,
        description="Public base URL of the approval API, included in the webhook payload.",
    )
    token_env: str | None = Field(
        default=None, description="Env var with a shared secret required by the approval API."
    )


class HitlConfig(_Strict):
    enabled: bool = True
    mode: Literal["cli", "webhook", "auto_approve", "auto_deny"] = "cli"
    timeout_seconds: float = Field(default=300.0, gt=0)
    tools: list[str] = Field(
        default_factory=list, description="Tool globs that always need approval."
    )
    rules: list[ApprovalRule] = Field(default_factory=list)
    destructive_hint: bool = Field(
        default=True,
        description="Require approval for tools whose MCP annotations set destructiveHint.",
    )
    webhook: WebhookConfig = Field(default_factory=WebhookConfig)


class AuditConfig(_Strict):
    enabled: bool = True
    path: str = ".sentinel/audit.db"
    log_arguments: bool = True
    log_results: bool = False
    max_payload_chars: int = Field(default=4000, ge=0)


class TasksConfig(_Strict):
    """Handling of the ``io.modelcontextprotocol/tasks`` extension."""

    bind_to_agent: bool = Field(
        default=True,
        description="Only the agent whose tools/call created a task may get, update or "
        "cancel it. Unknown task ids are refused.",
    )
    ttl_seconds: float = Field(
        default=3600.0, gt=0, description="How long the gateway remembers a task."
    )


class UpstreamConfig(_Strict):
    """The real MCP server that sentinel protects."""

    command: list[str] | None = Field(default=None, description="stdio server command + args.")
    env: dict[str, str] = Field(default_factory=dict)
    cwd: str | None = None
    url: str | None = Field(default=None, description="Streamable HTTP / SSE endpoint URL.")
    headers: dict[str, str] = Field(default_factory=dict)

    @field_validator("command", mode="before")
    @classmethod
    def _split_command(cls, value: Any) -> Any:
        if isinstance(value, str):
            import shlex

            return shlex.split(value)
        return value


class SentinelConfig(_Strict):
    version: int = 1
    default_agent: str = "default"
    default_action: Literal["allow", "deny"] = Field(
        default="deny",
        description="What happens to a tool that no allow/deny rule mentions.",
    )
    agents: dict[str, AgentPolicy] = Field(default_factory=dict)
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    hitl: HitlConfig = Field(default_factory=HitlConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    tasks: TasksConfig = Field(default_factory=TasksConfig)
    upstream: UpstreamConfig = Field(default_factory=UpstreamConfig)

    @model_validator(mode="after")
    def _check_inheritance(self) -> SentinelConfig:
        for name, agent in self.agents.items():
            for parent in agent.inherits:
                if parent not in self.agents:
                    raise ValueError(f"agent {name!r} inherits unknown agent {parent!r}")
        done: set[str] = set()

        def visit(name: str, path: tuple[str, ...]) -> None:
            if name in path:
                cycle = " -> ".join((*path[path.index(name) :], name))
                raise ValueError(f"agent inheritance cycle: {cycle}")
            if name in done:
                return
            for parent in self.agents[name].inherits:
                visit(parent, (*path, name))
            done.add(name)

        for agent_name in self.agents:
            visit(agent_name, ())
        return self

    @classmethod
    def from_yaml(cls, path: str | os.PathLike[str]) -> SentinelConfig:
        return load_config(path)

    @classmethod
    def from_yaml_string(cls, text: str) -> SentinelConfig:
        data = yaml.safe_load(text) or {}
        if not isinstance(data, dict):
            raise ValueError("sentinel config must be a YAML mapping")
        return cls.model_validate(_expand_env(data))


_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _expand_env(value: Any) -> Any:
    """Expand ``${VAR}`` and ``${VAR:-default}`` in every string of the config."""
    if isinstance(value, str):
        return _ENV_RE.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), value)
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    return value


def load_config(path: str | os.PathLike[str]) -> SentinelConfig:
    """Load and validate a ``sentinel.yaml`` file."""
    text = Path(path).read_text(encoding="utf-8")
    return SentinelConfig.from_yaml_string(text)
