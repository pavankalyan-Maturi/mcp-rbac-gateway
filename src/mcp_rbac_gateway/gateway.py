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

from .approvals import ApprovalRequest, ApprovalResponse, ApprovalStatus
from .audit import AuditEvent, AuditLog
from .config import SentinelConfig, load_config
from .context import CallContext, current_call_context
from .hitl import (
    ApprovalBroker,
    ApprovalConflict,
    ApprovalGate,
    Approver,
    approver_from_config,
    store_from_config,
)
from .mcp import RequestMeta, TaskRegistry, param_header_map
from .models import AuditDecision, CallVerdict, Finding, PolicyAction, ScanResult
from .policy import PolicyEngine
from .scanner import Scanner
from .sync import run_sync

if TYPE_CHECKING:  # pragma: no cover
    from .proxy import OnBlock

__all__ = [
    "ResultCheck",
    "Sentinel",
    "ToolBlockedError",
    "agent_context",
    "current_agent",
]

logger = logging.getLogger("mcp_rbac_gateway")
T = TypeVar("T")

_current_agent: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "mcp_rbac_gateway_agent", default=None
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
    """Raised by guarded functions when the gateway blocks a call."""

    def __init__(self, verdict: CallVerdict | None, reason: str, decision: AuditDecision):
        super().__init__(f"[mcp-rbac-gateway] {decision.value}: {reason}")
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
        self.broker = broker or ApprovalBroker(
            store_from_config(self.config.hitl, self.config.audit.path)
        )
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
        self.tool_param_headers: dict[str, dict[str, tuple[str, ...]]] = {}
        self.tasks = TaskRegistry(default_ttl=self.config.tasks.ttl_seconds)

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
                headers = param_header_map(tool.get("inputSchema"))
                if headers:
                    self.tool_param_headers[name] = headers
                else:
                    self.tool_param_headers.pop(name, None)

    def visible_tools(
        self, agent_id: str | None, tools: Iterable[Mapping[str, Any]]
    ) -> list[Mapping[str, Any]]:
        return self.policy.filter_tools(agent_id, tools)

    @staticmethod
    def resolve_context(context: CallContext | None = None) -> CallContext:
        """``context`` if given, else the bound :func:`call_context`, with OTel trace filled in."""
        ctx = context or current_call_context() or CallContext()
        return ctx.with_trace()

    def agent_or_default(self, agent_id: str | None) -> str:
        return agent_id or current_agent() or self.config.default_agent

    # ---------------------------------------------------------------- checks

    async def check_call(
        self,
        agent_id: str | None,
        tool: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        context: CallContext | None = None,
        wait: bool = True,
    ) -> CallVerdict:
        """Run policy, input scanning and approval for one call.

        When the call needs approval, the request is written to the audit trail
        (decision ``pending_approval``) and then:

        * ``wait=True`` (default): wait for the approver; the verdict is
          ``approved``, ``denied_by_human`` or ``approval_timeout``.
        * ``wait=False``: store the request in the approval store and return at
          once with decision ``pending_approval`` and ``approval_id`` set. Pause
          your own way (LangGraph ``interrupt``, a Temporal signal ...) and
          finish with :meth:`resume_call`.
        """
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
            ctx = context or current_call_context() or CallContext()
            request = ApprovalRequest(
                agent_id=agent,
                tool=tool,
                arguments=safe_args,
                reason=reason,
                timeout_seconds=self.config.hitl.timeout_seconds,
                tenant_id=ctx.tenant_id,
                session_id=ctx.session_id,
                request_id=ctx.request_id,
                traceparent=ctx.traceparent,
            )
            requested = CallVerdict(
                agent_id=agent,
                tool=tool,
                decision=AuditDecision.PENDING_APPROVAL,
                reason=f"approval requested: {reason}",
                arguments=safe_args,
                findings=findings,
                approval_id=request.id,
            )
            if not wait:
                self.broker.register(request)
                await self.record(requested, context=ctx)
                return requested
            await self.record(requested, context=ctx)
            outcome = await self.gate.review(agent, tool, safe_args, reason, request=request)
            return CallVerdict(
                agent_id=agent,
                tool=tool,
                decision=outcome.decision,
                reason=outcome.reason,
                arguments=safe_args,
                findings=findings,
                approver=outcome.approver,
                approval_id=request.id,
            )

        return CallVerdict(
            agent_id=agent,
            tool=tool,
            decision=AuditDecision.ALLOWED,
            reason=f"{decision.reason} ({decision.rule})",
            arguments=safe_args,
            findings=findings,
        )

    def check_method(
        self,
        agent_id: str | None,
        method: str,
        target: str,
        *,
        skill: str | None = None,
        scan: Any = None,
    ) -> CallVerdict:
        """Policy (and optional input scan) for a JSON-RPC method other than ``tools/call``.

        ``target`` is what the audit trail shows in its ``tool`` column: the
        skill path, the task's original tool, or the method itself. ``skill``
        is checked against the agent's ``skills`` rules. ``scan`` is any
        client-supplied payload (e.g. ``tasks/update`` ``inputResponses``) to
        redact and, when ``scan_inputs_for_injection`` is on, score.
        """
        agent = self.agent_or_default(agent_id)
        findings: list[Finding] = []
        safe: dict[str, Any] = {}
        injection_score = 0.0
        if scan is not None:
            result = self.scanner.scan_input({"input": scan})
            safe = result.payload
            findings = list(result.findings)
            injection_score = result.injection_score

        def verdict(decision: AuditDecision, reason: str) -> CallVerdict:
            return CallVerdict(
                agent_id=agent,
                tool=target,
                method=method,
                decision=decision,
                reason=reason,
                arguments=safe,
                findings=findings,
            )

        decision = self.policy.evaluate_method(agent, method)
        if decision.action is PolicyAction.DENY:
            return verdict(AuditDecision.BLOCKED_POLICY, f"{decision.reason} ({decision.rule})")
        if skill is not None:
            decision = self.policy.evaluate_skill(agent, skill)
            if decision.action is PolicyAction.DENY:
                return verdict(AuditDecision.BLOCKED_POLICY, f"{decision.reason} ({decision.rule})")
        inj = self.config.scanner.prompt_injection
        if (
            scan is not None
            and self.config.scanner.scan_inputs_for_injection
            and inj.action == "block"
            and self.scanner.is_injection(injection_score)
        ):
            return verdict(
                AuditDecision.BLOCKED_INJECTION,
                f"possible prompt injection in {method} input (score {injection_score:.2f})",
            )
        return verdict(AuditDecision.ALLOWED, f"{decision.reason} ({decision.rule})")

    def visible_skills(
        self, agent_id: str | None, skills: Iterable[Mapping[str, Any]]
    ) -> list[Mapping[str, Any]]:
        """Drop ``skills/list`` entries the agent may not read."""
        from .mcp import skill_path

        out = []
        for entry in skills:
            path = skill_path(str(entry.get("uri", "")))
            if path is None or self.policy.evaluate_skill(agent_id, path).allowed:
                out.append(entry)
        return out

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

    async def record(self, verdict: CallVerdict, **kwargs: Any) -> None:
        """Write one audit row. Takes the keyword arguments of :meth:`build_event`.

        ``session_id`` and ``request_id`` given here win over ``context``;
        ``context`` defaults to the one bound with :func:`call_context`.
        """
        if self.audit is None:
            return
        try:
            await self.audit.record(self.build_event(verdict, **kwargs))
        except Exception:  # pragma: no cover - auditing must never break a call
            logger.exception("failed to write audit event")

    def record_sync(self, verdict: CallVerdict, **kwargs: Any) -> None:
        """Blocking form of :meth:`record`, for sync code."""
        if self.audit is None:
            return
        try:
            self.audit.record_sync(self.build_event(verdict, **kwargs))
        except Exception:  # pragma: no cover - auditing must never break a call
            logger.exception("failed to write audit event")

    def build_event(
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
        meta: RequestMeta | None = None,
        context: CallContext | None = None,
    ) -> AuditEvent:
        """The audit row for ``verdict``; see :meth:`record`."""
        ctx = context or current_call_context() or CallContext()
        meta = meta or RequestMeta()
        safe_meta = None
        if meta.raw:
            safe_meta = self.scanner.redact(meta.raw, direction="input").payload
        findings = list(verdict.findings)
        injection_score = 0.0
        if result_check is not None:
            findings.extend(result_check.findings)
            injection_score = result_check.injection_score
        return AuditEvent(
            agent_id=verdict.agent_id,
            tool=verdict.tool,
            decision=decision or verdict.decision,
            reason=reason or verdict.reason,
            latency_ms=round(latency_ms, 3) if latency_ms is not None else None,
            transport=transport,
            request_id=str(request_id) if request_id is not None else ctx.request_id,
            session_id=session_id if session_id is not None else ctx.session_id,
            approver=verdict.approver,
            arguments=verdict.arguments,
            result=result,
            findings=findings,
            injection_score=injection_score,
            is_error=is_error,
            method=verdict.method,
            protocol_version=meta.protocol_version,
            client_name=meta.client_name,
            client_version=meta.client_version,
            traceparent=meta.traceparent or ctx.traceparent,
            tracestate=meta.tracestate,
            meta=safe_meta,
            tenant_id=ctx.tenant_id,
            labels=dict(ctx.labels),
            approval_id=verdict.approval_id,
        )

    # ------------------------------------------------------------- pipeline

    async def call(
        self,
        tool: str,
        arguments: Mapping[str, Any],
        fn: Callable[[dict[str, Any]], Awaitable[T]],
        *,
        agent_id: str | None = None,
        transport: str = "python",
        context: CallContext | None = None,
        wait: bool = True,
    ) -> T:
        """Guard an arbitrary async callable end to end.

        ``fn`` receives the (possibly redacted) arguments. Raises
        :class:`ToolBlockedError` when the call or its output is blocked.
        ``context`` (default: the one bound with :func:`call_context`) is
        written to every audit row this call produces.
        """
        ctx = self.resolve_context(context)
        started = time.perf_counter()
        verdict = await self.check_call(agent_id, tool, arguments, context=ctx, wait=wait)
        if verdict.pending:
            raise ToolBlockedError(verdict, verdict.reason, verdict.decision)
        if not verdict.allowed:
            await self.record(
                verdict,
                latency_ms=(time.perf_counter() - started) * 1000,
                transport=transport,
                context=ctx,
            )
            raise ToolBlockedError(verdict, verdict.reason, verdict.decision)
        return await self._run_checked(fn, verdict, started, transport, ctx)

    async def _run_checked(
        self,
        fn: Callable[[dict[str, Any]], Awaitable[T]],
        verdict: CallVerdict,
        started: float,
        transport: str,
        ctx: CallContext,
    ) -> T:
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
                context=ctx,
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
                context=ctx,
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
            context=ctx,
        )
        return check.payload  # type: ignore[no-any-return]

    # ------------------------------------------------------------- sync API

    def check_call_sync(
        self,
        agent_id: str | None,
        tool: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        context: CallContext | None = None,
        wait: bool = True,
    ) -> CallVerdict:
        """Blocking form of :meth:`check_call`. See :func:`run_sync` for loop handling."""
        return run_sync(
            lambda: self.check_call(agent_id, tool, arguments, context=context, wait=wait)
        )

    def call_sync(
        self,
        tool: str,
        arguments: Mapping[str, Any],
        fn: Callable[[dict[str, Any]], T],
        *,
        agent_id: str | None = None,
        transport: str = "python",
        context: CallContext | None = None,
        wait: bool = True,
    ) -> T:
        """Blocking form of :meth:`call` for a plain (sync) function.

        The policy check (and any approval wait) runs through :func:`run_sync`;
        ``fn`` itself runs in the calling thread, so thread-locals and
        non-thread-safe clients keep working.
        """
        ctx = self.resolve_context(context)
        started = time.perf_counter()
        verdict = run_sync(
            lambda: self.check_call(agent_id, tool, arguments, context=ctx, wait=wait)
        )
        if verdict.pending:
            raise ToolBlockedError(verdict, verdict.reason, verdict.decision)
        if not verdict.allowed:
            self.record_sync(
                verdict,
                latency_ms=(time.perf_counter() - started) * 1000,
                transport=transport,
                context=ctx,
            )
            raise ToolBlockedError(verdict, verdict.reason, verdict.decision)
        return self._run_checked_sync(fn, verdict, started, transport, ctx)

    def _run_checked_sync(
        self,
        fn: Callable[[dict[str, Any]], T],
        verdict: CallVerdict,
        started: float,
        transport: str,
        ctx: CallContext,
    ) -> T:
        try:
            result = fn(verdict.arguments)
        except Exception as exc:
            self.record_sync(
                verdict,
                decision=AuditDecision.ERROR,
                reason=f"{type(exc).__name__}: {exc}",
                latency_ms=(time.perf_counter() - started) * 1000,
                transport=transport,
                is_error=True,
                context=ctx,
            )
            raise
        check = self.check_result(result)
        latency = (time.perf_counter() - started) * 1000
        if check.blocked:
            self.record_sync(
                verdict,
                decision=AuditDecision.BLOCKED_INJECTION,
                reason=check.reason,
                latency_ms=latency,
                transport=transport,
                result_check=check,
                context=ctx,
            )
            raise ToolBlockedError(
                verdict, check.reason or "blocked", AuditDecision.BLOCKED_INJECTION
            )
        self.record_sync(
            verdict,
            latency_ms=latency,
            transport=transport,
            result=check.payload,
            result_check=check,
            context=ctx,
        )
        return check.payload  # type: ignore[no-any-return]

    # ------------------------------------------------------- resumed approvals

    def _resolve_pending(
        self, approval_id: str, response: ApprovalResponse
    ) -> tuple[CallVerdict, CallContext]:
        record = self.broker.record(approval_id)
        if record is None:
            raise LookupError(f"no approval request {approval_id}")
        request = record.request
        ctx = CallContext(
            tenant_id=request.tenant_id,
            session_id=request.session_id,
            request_id=request.request_id,
            traceparent=request.traceparent,
        )

        def verdict(decision: AuditDecision, reason: str, approver: str | None) -> CallVerdict:
            return CallVerdict(
                agent_id=request.agent_id,
                tool=request.tool,
                method=request.method,
                decision=decision,
                reason=reason,
                arguments=request.arguments,
                approver=approver,
                approval_id=request.id,
            )

        if not self.broker.resolve(approval_id, response):
            current = self.broker.record(approval_id)
            status = current.status if current else ApprovalStatus.EXPIRED
            if status is ApprovalStatus.EXPIRED:
                timeout = verdict(
                    AuditDecision.APPROVAL_TIMEOUT,
                    f"no approval within {request.timeout_seconds:g}s ({request.reason})",
                    None,
                )
                return timeout, ctx
            raise ApprovalConflict(approval_id, status)
        comment = f" ({response.comment})" if response.comment else ""
        if response.approved:
            return (
                verdict(
                    AuditDecision.APPROVED,
                    f"approved: {request.reason}{comment}",
                    response.approver,
                ),
                ctx,
            )
        return (
            verdict(
                AuditDecision.DENIED_BY_HUMAN,
                f"denied by {response.approver or 'approver'}{comment}",
                response.approver,
            ),
            ctx,
        )

    async def resume_call(
        self,
        approval_id: str,
        response: ApprovalResponse | bool,
        fn: Callable[[dict[str, Any]], Awaitable[T]] | None = None,
        *,
        transport: str = "python",
    ) -> Any:
        """Finish a call that ``check_call(..., wait=False)`` left pending.

        Decides the stored request (first decision wins: a second one raises
        :class:`ApprovalConflict`) and writes the decision to the audit trail
        with the tenant, session and request ids of the original call.

        Without ``fn`` this returns the :class:`CallVerdict`. With ``fn``, an
        approved call runs ``fn(arguments)`` and returns its scanned result,
        exactly like :meth:`call`; a denied or expired one raises
        :class:`ToolBlockedError`.
        """
        if isinstance(response, bool):
            response = ApprovalResponse(approved=response)
        started = time.perf_counter()
        verdict, ctx = self._resolve_pending(approval_id, response)
        if fn is None or not verdict.allowed:
            await self.record(verdict, transport=transport, context=ctx)
            if fn is None:
                return verdict
            raise ToolBlockedError(verdict, verdict.reason, verdict.decision)
        return await self._run_checked(fn, verdict, started, transport, ctx)

    def resume_call_sync(
        self,
        approval_id: str,
        response: ApprovalResponse | bool,
        fn: Callable[[dict[str, Any]], T] | None = None,
        *,
        transport: str = "python",
    ) -> Any:
        """Blocking form of :meth:`resume_call`; ``fn`` runs in the calling thread."""
        if isinstance(response, bool):
            response = ApprovalResponse(approved=response)
        started = time.perf_counter()
        verdict, ctx = self._resolve_pending(approval_id, response)
        if fn is None or not verdict.allowed:
            self.record_sync(verdict, transport=transport, context=ctx)
            if fn is None:
                return verdict
            raise ToolBlockedError(verdict, verdict.reason, verdict.decision)
        return self._run_checked_sync(fn, verdict, started, transport, ctx)

    def guard(
        self,
        fn: Callable[..., Any] | None = None,
        *,
        tool: str | None = None,
        agent_id: str | None = None,
        on_block: OnBlock = "raise",
        context: CallContext | None = None,
    ) -> Any:
        """Decorator form of :meth:`call`. See :func:`mcp_rbac_gateway.proxy.guard`."""
        from .proxy import guard

        decorator = guard(self, tool=tool, agent_id=agent_id, on_block=on_block, context=context)
        return decorator(fn) if fn is not None else decorator

    def close(self) -> None:
        if self.audit is not None:
            self.audit.close()
