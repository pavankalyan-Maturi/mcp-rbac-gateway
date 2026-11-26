"""The :class:`Sentinel` facade that ties policy, scanner, HITL and audit together.

Both transports (the MCP proxy and the Python decorator) go through the same
two calls, so a rule behaves identically no matter how a tool is reached:

1. :meth:`Sentinel.check_call` - before the tool runs:
   policy -> input redaction -> (optional) input injection scan -> approval.
2. :meth:`Sentinel.check_result` - after the tool returns:
   output redaction -> prompt-injection scoring.

:meth:`Sentinel.record` then writes the outcome to the audit trail.
"""

from __future__ import annotations

import contextvars
import logging
import os
import time
from collections.abc import Awaitable, Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, Literal, TypeVar

from pydantic import BaseModel, Field

from .audit import AuditEvent, AuditLog
from .config import SentinelConfig, load_config
from .hitl import ApprovalBroker, ApprovalGate, Approver, approver_from_config
from .models import AuditDecision, CallVerdict, Finding, PolicyAction, ScanResult
from .policy import PolicyEngine
from .scanner import Scanner

if TYPE_CHECKING:  # pragma: no cover
    from .proxy import OnBlock

__all__ = [
    "ResultCheck",
    "Sentinel",
    "ToolBlockedError",
    "agent_context",
    "current_agent",
]

logger = logging.getLogger("mcp_sentinel")
T = TypeVar("T")

_current_agent: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "mcp_sentinel_agent", default=None
)


def current_agent() -> str | None:
    """The agent identity bound with :func:`agent_context`, if any."""
    return _current_agent.get()


@contextmanager
def agent_context(agent_id: str) -> Iterator[None]:
    """Bind an agent identity to every guarded call made inside the block.

    Works across ``await`` and in worker threads started with
    ``asyncio.to_thread`` / LangGraph's executor, because it uses ``contextvars``.
    """
    token = _current_agent.set(agent_id)
    try:
        yield
    finally:
        _current_agent.reset(token)


class ToolBlockedError(PermissionError):
    """Raised by guarded functions when sentinel blocks a call."""

    def __init__(self, verdict: CallVerdict | None, reason: str, decision: AuditDecision):
        super().__init__(f"[mcp-sentinel] {decision.value}: {reason}")
        self.verdict = verdict
        self.reason = reason
        self.decision = decision


class ResultCheck(BaseModel):
    payload: Any
    findings: list[Finding] = Field(default_factory=list)
    injection_score: float = 0.0
    blocked: bool = False
    reason: str | None = None


class Sentinel:
    """Security gateway for MCP tool calls.

    >>> sentinel = Sentinel.from_yaml("sentinel.yaml")          # doctest: +SKIP
    >>> v = await sentinel.check_call("researcher", "read_file", {"path": "/x"})  # doctest: +SKIP
    """

    def __init__(
        self,
        config: SentinelConfig | None = None,
        *,
        approver: Approver | None = None,
        audit: AuditLog | Literal[False] | None = None,
        broker: ApprovalBroker | None = None,
    ) -> None:
        self.config = config or SentinelConfig()
        self.policy = PolicyEngine(self.config)
        self.scanner = Scanner(self.config.scanner)
        self.broker = broker or ApprovalBroker()
        self.gate = ApprovalGate(
            self.config.hitl, approver or approver_from_config(self.config.hitl, self.broker)
        )
        if audit is False:
            self.audit: AuditLog | None = None
        elif audit is None:
            self.audit = (
                AuditLog.from_config(self.config.audit) if self.config.audit.enabled else None
            )
        else:
            self.audit = audit
        self.tool_annotations: dict[str, dict[str, Any]] = {}

    @classmethod
    def from_yaml(cls, path: str | os.PathLike[str], **kwargs: Any) -> Sentinel:
        return cls(load_config(path), **kwargs)

    # ----------------------------------------------------------- tool catalog

    def register_tools(self, tools: Iterable[Mapping[str, Any]]) -> None:
        """Remember MCP tool annotations (``destructiveHint`` etc.) from ``tools/list``."""
        for tool in tools:
            name = tool.get("name")
            if isinstance(name, str):
                annotations = tool.get("annotations")
                self.tool_annotations[name] = (
                    dict(annotations) if isinstance(annotations, dict) else {}
                )

    def visible_tools(
        self, agent_id: str | None, tools: Iterable[Mapping[str, Any]]
    ) -> list[Mapping[str, Any]]:
        return self.policy.filter_tools(agent_id, tools)

    def agent_or_default(self, agent_id: str | None) -> str:
        return agent_id or current_agent() or self.config.default_agent

    # ---------------------------------------------------------------- checks

    async def check_call(
        self,
        agent_id: str | None,
        tool: str,
        arguments: Mapping[str, Any] | None = None,
    ) -> CallVerdict:
        """Run policy, input scanning and approval for one call."""
        agent = self.agent_or_default(agent_id)
        raw_args = dict(arguments or {})

        decision = self.policy.evaluate(agent, tool, raw_args)
        scan = self.scanner.scan_input(raw_args)
        safe_args: dict[str, Any] = scan.payload
        findings = list(scan.findings)

        if decision.action is PolicyAction.DENY:
            return CallVerdict(
                agent_id=agent,
                tool=tool,
                decision=AuditDecision.BLOCKED_POLICY,
                reason=f"{decision.reason} ({decision.rule})",
                arguments=safe_args,
                findings=findings,
            )

        inj = self.config.scanner.prompt_injection
        if (
            self.config.scanner.scan_inputs_for_injection
            and inj.action == "block"
            and self.scanner.is_injection(scan.injection_score)
        ):
            return CallVerdict(
                agent_id=agent,
                tool=tool,
                decision=AuditDecision.BLOCKED_INJECTION,
                reason=f"possible prompt injection in arguments (score {scan.injection_score:.2f})",
                arguments=safe_args,
                findings=findings,
            )

        reason = self.gate.approval_reason(
            tool, raw_args, decision, self.tool_annotations.get(tool)
        )
        if reason is not None:
            outcome = await self.gate.review(agent, tool, safe_args, reason)
            return CallVerdict(
                agent_id=agent,
                tool=tool,
                decision=outcome.decision,
                reason=outcome.reason,
                arguments=safe_args,
                findings=findings,
                approver=outcome.approver,
            )

        return CallVerdict(
            agent_id=agent,
            tool=tool,
            decision=AuditDecision.ALLOWED,
            reason=f"{decision.reason} ({decision.rule})",
            arguments=safe_args,
            findings=findings,
        )

    def check_result(self, result: Any) -> ResultCheck:
        """Redact and score a tool result."""
        scan: ScanResult = self.scanner.scan_output(result)
        inj = self.config.scanner.prompt_injection
        if self.scanner.is_injection(scan.injection_score):
            detectors = sorted({f.detector for f in scan.injection_findings})
            reason = (
                f"possible prompt injection in tool output "
                f"(score {scan.injection_score:.2f}: {', '.join(detectors)})"
            )
            if inj.action == "block":
                return ResultCheck(
                    payload=scan.payload,
                    findings=scan.findings,
                    injection_score=scan.injection_score,
                    blocked=True,
                    reason=reason,
                )
            logger.warning("%s", reason)
        return ResultCheck(
            payload=scan.payload, findings=scan.findings, injection_score=scan.injection_score
        )

    # ----------------------------------------------------------------- audit

    async def record(
        self,
        verdict: CallVerdict,
        *,
        decision: AuditDecision | None = None,
        reason: str | None = None,
        latency_ms: float | None = None,
        transport: str = "python",
        request_id: Any = None,
        session_id: str | None = None,
        result: Any = None,
        result_check: ResultCheck | None = None,
        is_error: bool = False,
    ) -> None:
        if self.audit is None:
            return
        findings = list(verdict.findings)
        injection_score = 0.0
        if result_check is not None:
            findings.extend(result_check.findings)
            injection_score = result_check.injection_score
        event = AuditEvent(
            agent_id=verdict.agent_id,
            tool=verdict.tool,
            decision=decision or verdict.decision,
            reason=reason or verdict.reason,
            latency_ms=round(latency_ms, 3) if latency_ms is not None else None,
            transport=transport,
            request_id=None if request_id is None else str(request_id),
            session_id=session_id,
            approver=verdict.approver,
            arguments=verdict.arguments,
            result=result,
            findings=findings,
            injection_score=injection_score,
            is_error=is_error,
        )
        try:
            await self.audit.record(event)
        except Exception:  # pragma: no cover - auditing must never break a call
            logger.exception("failed to write audit event")

    # ------------------------------------------------------------- pipeline

    async def call(
        self,
        tool: str,
        arguments: Mapping[str, Any],
        fn: Callable[[dict[str, Any]], Awaitable[T]],
        *,
        agent_id: str | None = None,
        transport: str = "python",
    ) -> T:
        """Guard an arbitrary async callable end to end.

        ``fn`` receives the (possibly redacted) arguments. Raises
        :class:`ToolBlockedError` when the call or its output is blocked.
        """
        started = time.perf_counter()
        verdict = await self.check_call(agent_id, tool, arguments)
        if not verdict.allowed:
            await self.record(
                verdict,
                latency_ms=(time.perf_counter() - started) * 1000,
                transport=transport,
            )
            raise ToolBlockedError(verdict, verdict.reason, verdict.decision)
        try:
            result = await fn(verdict.arguments)
        except Exception as exc:
            await self.record(
                verdict,
                decision=AuditDecision.ERROR,
                reason=f"{type(exc).__name__}: {exc}",
                latency_ms=(time.perf_counter() - started) * 1000,
                transport=transport,
                is_error=True,
            )
            raise
        check = self.check_result(result)
        latency = (time.perf_counter() - started) * 1000
        if check.blocked:
            await self.record(
                verdict,
                decision=AuditDecision.BLOCKED_INJECTION,
                reason=check.reason,
                latency_ms=latency,
                transport=transport,
                result_check=check,
            )
            raise ToolBlockedError(
                verdict, check.reason or "blocked", AuditDecision.BLOCKED_INJECTION
            )
        await self.record(
            verdict,
            latency_ms=latency,
            transport=transport,
            result=check.payload,
            result_check=check,
        )
        return check.payload  # type: ignore[no-any-return]

    def guard(
        self,
        fn: Callable[..., Any] | None = None,
        *,
        tool: str | None = None,
        agent_id: str | None = None,
        on_block: OnBlock = "raise",
    ) -> Any:
        """Decorator form of :meth:`call`. See :func:`mcp_sentinel.proxy.guard`."""
        from .proxy import guard

        decorator = guard(self, tool=tool, agent_id=agent_id, on_block=on_block)
        return decorator(fn) if fn is not None else decorator

    def close(self) -> None:
        if self.audit is not None:
            self.audit.close()
