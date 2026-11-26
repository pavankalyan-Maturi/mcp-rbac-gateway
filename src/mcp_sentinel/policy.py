"""Policy & RBAC engine.

Rules are evaluated in a fixed, easy-to-reason-about order:

1. **deny** - if any ``deny`` glob matches the tool name, the call is denied.
   Deny always wins, including over inherited ``allow`` rules.
2. **allow** - if any ``allow`` glob matches, the call may proceed.
   Otherwise ``default_action`` decides (``deny`` by default).
3. **arguments** - every constraint whose tool glob matches is checked against
   the raw (un-redacted) arguments. Any violation denies the call.
4. **require_approval** - if a ``require_approval`` glob matches, the call is
   allowed only after a human approves it (see :mod:`mcp_sentinel.hitl`).

Agents that are not listed in the config are evaluated with the policy of
``default_agent``. If that agent is not defined either, only
``default_action`` applies.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from functools import lru_cache
from typing import Any

from .config import AgentPolicy, ArgumentConstraint, SentinelConfig
from .models import PolicyAction, PolicyDecision

__all__ = ["EffectivePolicy", "PolicyEngine", "as_text", "compile_regex", "match_any"]


def match_any(name: str, patterns: Iterable[str]) -> str | None:
    """Return the first glob in ``patterns`` that matches ``name`` (case-sensitive)."""
    for pattern in patterns:
        if fnmatchcase(name, pattern):
            return pattern
    return None


@lru_cache(maxsize=1024)
def compile_regex(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


def as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)) or value is None:
        return json.dumps(value)
    return json.dumps(value, sort_keys=True, default=str)


@dataclass
class EffectivePolicy:
    """An agent's rules after inheritance has been flattened."""

    agent_id: str
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    require_approval: list[str] = field(default_factory=list)
    arguments: list[tuple[str, dict[str, ArgumentConstraint]]] = field(default_factory=list)


class PolicyEngine:
    """Evaluates tool calls against the ``agents`` section of a :class:`SentinelConfig`."""

    def __init__(self, config: SentinelConfig) -> None:
        self.config = config
        self._cache: dict[str, EffectivePolicy] = {}

    def resolve_agent(self, agent_id: str | None) -> str:
        """Map an incoming identity to the name of the policy that governs it."""
        if agent_id and agent_id in self.config.agents:
            return agent_id
        return self.config.default_agent

    def effective_policy(self, agent_id: str | None) -> EffectivePolicy:
        name = self.resolve_agent(agent_id)
        cached = self._cache.get(name)
        if cached is not None:
            return cached
        policy = EffectivePolicy(agent_id=name)
        self._flatten(name, policy, seen=set())
        self._cache[name] = policy
        return policy

    def _flatten(self, name: str, out: EffectivePolicy, seen: set[str]) -> None:
        if name in seen:
            return
        seen.add(name)
        agent: AgentPolicy | None = self.config.agents.get(name)
        if agent is None:
            return
        out.allow.extend(agent.allow)
        out.deny.extend(agent.deny)
        out.require_approval.extend(agent.require_approval)
        out.arguments.extend(agent.arguments.items())
        for parent in agent.inherits:
            self._flatten(parent, out, seen)

    # ------------------------------------------------------------------ checks

    def is_tool_visible(self, agent_id: str | None, tool: str) -> bool:
        """Whether ``tool`` should appear in ``tools/list`` for this agent."""
        policy = self.effective_policy(agent_id)
        if match_any(tool, policy.deny):
            return False
        if match_any(tool, policy.allow):
            return True
        return self.config.default_action == "allow"

    def filter_tools(
        self, agent_id: str | None, tools: Iterable[Mapping[str, Any]]
    ) -> list[Mapping[str, Any]]:
        """Drop tool descriptors (``{"name": ...}``) the agent may never call."""
        return [t for t in tools if self.is_tool_visible(agent_id, str(t.get("name", "")))]

    def evaluate(
        self, agent_id: str | None, tool: str, arguments: Mapping[str, Any] | None = None
    ) -> PolicyDecision:
        """Decide whether ``agent_id`` may call ``tool`` with ``arguments``."""
        arguments = arguments or {}
        policy = self.effective_policy(agent_id)
        who = policy.agent_id

        denied_by = match_any(tool, policy.deny)
        if denied_by:
            return PolicyDecision(
                action=PolicyAction.DENY,
                reason=f"tool '{tool}' is denied for agent '{who}'",
                rule=f"agents.{who}.deny[{denied_by}]",
            )

        allowed_by = match_any(tool, policy.allow)
        if not allowed_by and self.config.default_action == "deny":
            return PolicyDecision(
                action=PolicyAction.DENY,
                reason=f"tool '{tool}' is not in the allowlist for agent '{who}'",
                rule="default_action",
            )

        violation = self._check_arguments(policy, tool, arguments)
        if violation is not None:
            return violation

        approval_by = match_any(tool, policy.require_approval)
        if approval_by:
            return PolicyDecision(
                action=PolicyAction.REQUIRE_APPROVAL,
                reason=f"tool '{tool}' requires human approval for agent '{who}'",
                rule=f"agents.{who}.require_approval[{approval_by}]",
            )

        return PolicyDecision(
            action=PolicyAction.ALLOW,
            reason="allowed by policy",
            rule=f"agents.{who}.allow[{allowed_by}]" if allowed_by else "default_action",
        )

    def _check_arguments(
        self, policy: EffectivePolicy, tool: str, arguments: Mapping[str, Any]
    ) -> PolicyDecision | None:
        who = policy.agent_id
        for tool_glob, constraints in policy.arguments:
            if not fnmatchcase(tool, tool_glob):
                continue
            for arg_name, constraint in constraints.items():
                rule = f"agents.{who}.arguments[{tool_glob}].{arg_name}"
                problem = _violates(constraint, arg_name, arguments)
                if problem:
                    return PolicyDecision(
                        action=PolicyAction.DENY,
                        reason=f"argument '{arg_name}' of '{tool}' {problem}",
                        rule=rule,
                    )
        return None


def _violates(
    constraint: ArgumentConstraint, name: str, arguments: Mapping[str, Any]
) -> str | None:
    if name not in arguments:
        return "is required" if constraint.required else None
    value = arguments[name]
    text = as_text(value)
    if constraint.allowed_values is not None and value not in constraint.allowed_values:
        return f"must be one of {constraint.allowed_values!r}"
    if constraint.max_length is not None and len(text) > constraint.max_length:
        return f"exceeds max length {constraint.max_length}"
    if constraint.pattern is not None and not compile_regex(constraint.pattern).fullmatch(text):
        return f"does not match required pattern /{constraint.pattern}/"
    if constraint.deny_pattern is not None and compile_regex(constraint.deny_pattern).search(text):
        return f"matches forbidden pattern /{constraint.deny_pattern}/"
    return None
