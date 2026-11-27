"""Human-in-the-loop approval gate.

When a call needs approval, the gate pauses it and asks an :class:`Approver`.
The call only reaches the upstream tool after an explicit *approve*; a deny,
an error, or a timeout all block it (fail closed).

Approvers shipped with the library:

* :class:`CLIApprover` - prompts on the controlling terminal (``/dev/tty``),
  so it works even while stdin/stdout carry the MCP stdio protocol.
* :class:`WebhookApprover` - POSTs the request to a URL (Slack relay, n8n,
  your own service...). The receiver either answers inline with
  ``{"approved": true}`` or later calls the approval API exposed by
  :func:`create_approval_router` (a FastAPI router).
* :class:`AutoApprover` and :class:`CallbackApprover` - for tests and custom logic.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import sys
import threading
from collections.abc import Awaitable, Callable, Mapping, Sequence
from fnmatch import fnmatchcase
from typing import IO, TYPE_CHECKING, Any, Protocol, runtime_checkable

import httpx
from pydantic import BaseModel

from .approvals import (
    ApprovalRecord,
    ApprovalRequest,
    ApprovalResponse,
    ApprovalStatus,
    ApprovalStore,
    MemoryApprovalStore,
    SqliteApprovalStore,
)
from .config import HitlConfig, WebhookConfig
from .models import AuditDecision, PolicyAction, PolicyDecision
from .policy import as_text, compile_regex, match_any

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import APIRouter

__all__ = [
    "ApprovalBroker",
    "ApprovalConflict",
    "ApprovalGate",
    "ApprovalOutcome",
    "ApprovalRequest",
    "ApprovalResponse",
    "ApprovalUnavailable",
    "Approver",
    "AutoApprover",
    "CLIApprover",
    "CallbackApprover",
    "WebhookApprover",
    "approver_from_config",
    "store_from_config",
    "create_approval_router",
]


class ApprovalOutcome(BaseModel):
    decision: AuditDecision
    reason: str
    approver: str | None = None


class ApprovalUnavailable(RuntimeError):
    """Raised by an approver that cannot ask anyone (e.g. no terminal attached)."""


@runtime_checkable
class Approver(Protocol):
    async def request_approval(self, request: ApprovalRequest) -> ApprovalResponse: ...


# ---------------------------------------------------------------- approvers


class AutoApprover:
    """Approves (or denies) everything. Useful in tests and CI."""

    def __init__(self, approve: bool = True, approver: str = "auto") -> None:
        self.approve = approve
        self.approver = approver
        self.requests: list[ApprovalRequest] = []

    async def request_approval(self, request: ApprovalRequest) -> ApprovalResponse:
        self.requests.append(request)
        return ApprovalResponse(approved=self.approve, approver=self.approver)


class CallbackApprover:
    """Delegates the decision to a sync or async callable returning ``bool`` or a response."""

    def __init__(
        self,
        callback: Callable[[ApprovalRequest], bool | ApprovalResponse | Awaitable[Any]],
        approver: str = "callback",
    ) -> None:
        self.callback = callback
        self.approver = approver

    async def request_approval(self, request: ApprovalRequest) -> ApprovalResponse:
        result = self.callback(request)
        if inspect.isawaitable(result):
            result = await result
        if isinstance(result, ApprovalResponse):
            return result
        return ApprovalResponse(approved=bool(result), approver=self.approver)


class CLIApprover:
    """Interactive ``[y/N]`` prompt on the controlling terminal."""

    def __init__(
        self,
        input_stream: IO[str] | None = None,
        output_stream: IO[str] | None = None,
    ) -> None:
        self._input = input_stream
        self._output = output_stream
        # A thread lock (not asyncio.Lock) so prompts are serialised even when
        # sync tools run their own event loops in worker threads.
        self._lock = threading.Lock()

    def _streams(self) -> tuple[IO[str], IO[str]]:
        if self._input is not None:
            return self._input, self._output or sys.stderr
        try:
            tty = open("/dev/tty", "r+", encoding="utf-8")  # noqa: SIM115
        except OSError as exc:
            raise ApprovalUnavailable("no terminal available for CLI approval") from exc
        return tty, tty

    def _prompt(self, request: ApprovalRequest) -> ApprovalResponse:
        inp, out = self._streams()
        args = json.dumps(request.arguments, indent=2, ensure_ascii=False, default=str)
        out.write(
            "\n\033[1;33m⚠  mcp-rbac-gateway: approval required\033[0m\n"
            f"  agent : {request.agent_id}\n"
            f"  tool  : {request.tool}\n"
            f"  reason: {request.reason}\n"
            f"  args  : {args.replace(chr(10), chr(10) + '          ')}\n"
            "Approve this call? [y/N] "
        )
        out.flush()
        answer = inp.readline().strip().lower()
        if inp is not self._input:
            inp.close()
        return ApprovalResponse(
            approved=answer in {"y", "yes"},
            approver=f"cli:{os.environ.get('USER', 'unknown')}",
        )

    def _prompt_locked(self, request: ApprovalRequest) -> ApprovalResponse:
        with self._lock:  # one prompt at a time
            return self._prompt(request)

    async def request_approval(self, request: ApprovalRequest) -> ApprovalResponse:
        return await asyncio.to_thread(self._prompt_locked, request)


class ApprovalConflict(RuntimeError):
    """The approval was already decided (or expired) by someone else."""

    def __init__(self, request_id: str, status: ApprovalStatus) -> None:
        super().__init__(f"approval {request_id} is already {status.value}")
        self.request_id = request_id
        self.status = status


class ApprovalBroker:
    """Pending approvals that the approval API, or any other process, can decide.

    Requests live in an :class:`~mcp_rbac_gateway.approvals.ApprovalStore`.
    A waiter in this process is woken at once when this broker resolves its
    request; otherwise it polls the store with backoff (``poll_interval`` up
    to ``max_poll_interval`` seconds), so a decision made by another replica
    sharing the store is picked up too.
    """

    def __init__(
        self,
        store: ApprovalStore | None = None,
        *,
        poll_interval: float = 0.05,
        max_poll_interval: float = 1.0,
    ) -> None:
        self.store: ApprovalStore = store or MemoryApprovalStore()
        self.poll_interval = poll_interval
        self.max_poll_interval = max_poll_interval
        self._waiters: dict[str, asyncio.Future[ApprovalResponse]] = {}

    def register(self, request: ApprovalRequest) -> None:
        """Store a pending request without waiting for it (``check_call(wait=False)``)."""
        self.store.put(request)

    def submit(self, request: ApprovalRequest) -> asyncio.Future[ApprovalResponse]:
        """Store a pending request and return a future resolved by this broker."""
        future: asyncio.Future[ApprovalResponse] = asyncio.get_running_loop().create_future()
        self._waiters[request.id] = future
        future.add_done_callback(lambda _f: self._waiters.pop(request.id, None))
        self.store.put(request)
        return future

    async def wait(self, request_id: str) -> ApprovalResponse:
        """Wait until the request is decided here or elsewhere.

        Raises :class:`asyncio.TimeoutError` if it expires first. The caller
        normally also wraps this in its own timeout.
        """
        interval = self.poll_interval
        change_hook = getattr(self.store, "wait_for_change", None)
        while True:
            future = self._waiters.get(request_id)
            if future is not None:
                try:
                    return await asyncio.wait_for(asyncio.shield(future), interval)
                except asyncio.TimeoutError:
                    pass
            elif change_hook is not None:
                await change_hook(request_id, interval)
            else:
                await asyncio.sleep(interval)
            record = self.store.get(request_id)
            if record is None:
                raise ApprovalUnavailable(f"approval request {request_id} is gone")
            if record.response is not None:
                return record.response
            if record.status is ApprovalStatus.EXPIRED:
                raise asyncio.TimeoutError
            interval = min(interval * 1.5, self.max_poll_interval)

    def discard(self, request_id: str) -> None:
        """Stop waiting here. The stored request then expires at its deadline."""
        future = self._waiters.pop(request_id, None)
        if future is not None and not future.done():
            future.cancel()

    def pending(self, scope: str | None = None) -> list[ApprovalRequest]:
        return self.store.list_pending(scope)

    def get(self, request_id: str) -> ApprovalRequest | None:
        """The request if it is still pending."""
        record = self.store.get(request_id)
        return record.request if record and record.status is ApprovalStatus.PENDING else None

    def record(self, request_id: str) -> ApprovalRecord | None:
        return self.store.get(request_id)

    def resolve(self, request_id: str, response: ApprovalResponse) -> bool:
        """Decide a request. First writer wins; returns False if it was not pending."""
        if not self.store.resolve(request_id, response):
            return False
        future = self._waiters.get(request_id)
        if future is not None and not future.done():
            future.get_loop().call_soon_threadsafe(_set_result, future, response)
        return True


def _set_result(future: asyncio.Future[ApprovalResponse], value: ApprovalResponse) -> None:
    if not future.done():
        future.set_result(value)


class WebhookApprover:
    """Sends approval requests to a webhook and waits for the decision.

    The webhook receives ``POST <url>`` with JSON::

        {
          "type": "mcp_rbac_gateway.approval_request",
          "request": {...ApprovalRequest...},
          "approve_url": "<callback_base_url>/approvals/<id>/approve",
          "deny_url": "<callback_base_url>/approvals/<id>/deny"
        }

    It can answer synchronously with ``{"approved": true|false}``, or answer
    ``202`` and decide later via the approval API.
    """

    def __init__(
        self,
        config: WebhookConfig,
        broker: ApprovalBroker | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.config = config
        self.broker = broker or ApprovalBroker()
        self._client = client

    async def request_approval(self, request: ApprovalRequest) -> ApprovalResponse:
        self.broker.submit(request)
        try:
            if self.config.url:
                inline = await self._notify(request)
                if inline is not None:
                    self.broker.resolve(request.id, inline)
                    return inline
            return await self.broker.wait(request.id)
        finally:
            self.broker.discard(request.id)

    async def _notify(self, request: ApprovalRequest) -> ApprovalResponse | None:
        base = (self.config.callback_base_url or "").rstrip("/")
        payload = {
            "type": "mcp_rbac_gateway.approval_request",
            "request": request.model_dump(mode="json"),
            "approve_url": f"{base}/approvals/{request.id}/approve" if base else None,
            "deny_url": f"{base}/approvals/{request.id}/deny" if base else None,
        }
        client = self._client or httpx.AsyncClient(timeout=10)
        try:
            resp = await client.post(
                str(self.config.url), json=payload, headers=self.config.headers
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise ApprovalUnavailable(f"approval webhook failed: {exc}") from exc
        finally:
            if self._client is None:
                await client.aclose()
        if resp.status_code == 200 and resp.content:
            try:
                body = resp.json()
            except ValueError:
                return None
            if isinstance(body, dict) and isinstance(body.get("approved"), bool):
                return ApprovalResponse.model_validate(body)
        return None


class ApprovalDecisionBody(BaseModel):
    """Optional JSON body for ``POST /approvals/{id}/approve|deny``."""

    approver: str | None = None
    comment: str | None = None


def bearer_dependency(token: str | None, what: str) -> Callable[..., None]:
    """A FastAPI dependency that checks ``Authorization: Bearer <token>`` (no-op if None)."""
    import hmac

    from fastapi import Header, HTTPException

    def check_token(authorization: str | None = Header(default=None)) -> None:
        if token is None:
            return
        expected = f"Bearer {token}"
        if authorization is None or not hmac.compare_digest(authorization, expected):
            raise HTTPException(status_code=401, detail=f"invalid {what} token")

    return check_token


async def resolve_scope(require_scope: Callable[[Any], Any] | None, request: Any) -> str | None:
    """Run a host's ``require_scope(request)`` hook (sync or async)."""
    if require_scope is None:
        return None
    scope = require_scope(request)
    if inspect.isawaitable(scope):
        scope = await scope
    return None if scope is None else str(scope)


def create_approval_router(
    broker: ApprovalBroker,
    token: str | None = None,
    *,
    require_scope: Callable[[Any], Any] | None = None,
    dependencies: Sequence[Any] = (),
) -> APIRouter:
    """FastAPI router exposing pending approvals.

    ``GET /approvals``, ``GET /approvals/{id}``, ``POST /approvals/{id}/approve``
    and ``POST /approvals/{id}/deny``. When ``token`` is set, requests must send
    ``Authorization: Bearer <token>``. ``dependencies`` adds your own FastAPI
    dependencies (e.g. ``[Depends(current_user)]``) to every route.

    ``require_scope(request) -> tenant_id | None`` (sync or async) limits a
    caller to one tenant's approvals: others are listed as absent and answer
    ``404``. Deciding a request that was already decided or has expired
    answers ``409``.
    """
    from .api import approval_routes

    router: APIRouter = approval_routes(
        broker, token, require_scope=require_scope, dependencies=dependencies
    )
    return router


def approver_from_config(config: HitlConfig, broker: ApprovalBroker | None = None) -> Approver:
    if config.mode == "auto_approve":
        return AutoApprover(True)
    if config.mode == "auto_deny":
        return AutoApprover(False)
    if config.mode == "webhook":
        return WebhookApprover(config.webhook, broker=broker)
    if config.mode == "api":
        # Wait for the approval API only: no webhook, no terminal.
        return WebhookApprover(WebhookConfig(), broker=broker)
    return CLIApprover()


def store_from_config(config: HitlConfig, audit_path: str) -> ApprovalStore:
    """``hitl.store``: ``memory`` (default) or ``sqlite`` (``store_path``, else the audit file)."""
    if config.store == "sqlite":
        return SqliteApprovalStore(config.store_path or audit_path)
    return MemoryApprovalStore()


# --------------------------------------------------------------------- gate


class ApprovalGate:
    """Decides *whether* a call needs approval, and runs the approval if so."""

    def __init__(self, config: HitlConfig, approver: Approver | None = None) -> None:
        self.config = config
        self.approver = approver or approver_from_config(config)

    def approval_reason(
        self,
        tool: str,
        arguments: Mapping[str, Any],
        policy: PolicyDecision | None = None,
        annotations: Mapping[str, Any] | None = None,
    ) -> str | None:
        """Return why approval is needed, or ``None`` if the call may go straight through."""
        if not self.config.enabled:
            return None
        if policy is not None and policy.action is PolicyAction.REQUIRE_APPROVAL:
            return policy.reason
        glob = match_any(tool, self.config.tools)
        if glob:
            return f"tool '{tool}' matches hitl.tools[{glob}]"
        for rule in self.config.rules:
            if not fnmatchcase(tool, rule.tool):
                continue
            if all(
                name in arguments and compile_regex(rx).search(as_text(arguments[name]))
                for name, rx in rule.when.items()
            ):
                return rule.reason or f"tool '{tool}' matches an approval rule"
        if (
            self.config.destructive_hint
            and annotations
            and annotations.get("destructiveHint") is True
            and annotations.get("readOnlyHint") is not True
        ):
            return f"tool '{tool}' is annotated as destructive"
        return None

    async def review(
        self,
        agent_id: str,
        tool: str,
        display_arguments: dict[str, Any],
        reason: str,
        *,
        request: ApprovalRequest | None = None,
    ) -> ApprovalOutcome:
        request = request or ApprovalRequest(
            agent_id=agent_id,
            tool=tool,
            arguments=display_arguments,
            reason=reason,
            timeout_seconds=self.config.timeout_seconds,
        )
        try:
            response = await asyncio.wait_for(
                self.approver.request_approval(request), timeout=self.config.timeout_seconds
            )
        except asyncio.TimeoutError:
            return ApprovalOutcome(
                decision=AuditDecision.APPROVAL_TIMEOUT,
                reason=f"no approval within {self.config.timeout_seconds:g}s ({reason})",
            )
        except ApprovalUnavailable as exc:
            return ApprovalOutcome(
                decision=AuditDecision.DENIED_BY_HUMAN, reason=f"approval unavailable: {exc}"
            )
        if response.approved:
            return ApprovalOutcome(
                decision=AuditDecision.APPROVED,
                reason=f"approved: {reason}"
                + (f" ({response.comment})" if response.comment else ""),
                approver=response.approver,
            )
        return ApprovalOutcome(
            decision=AuditDecision.DENIED_BY_HUMAN,
            reason=f"denied by {response.approver or 'approver'}"
            + (f": {response.comment}" if response.comment else ""),
            approver=response.approver,
        )
