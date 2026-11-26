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
import time
import uuid
from collections.abc import Awaitable, Callable, Mapping
from fnmatch import fnmatchcase
from typing import IO, TYPE_CHECKING, Any, Protocol, runtime_checkable

import httpx
from pydantic import BaseModel, Field

from .config import HitlConfig, WebhookConfig
from .models import AuditDecision, PolicyAction, PolicyDecision
from .policy import as_text, compile_regex, match_any

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import APIRouter

__all__ = [
    "ApprovalBroker",
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
    "create_approval_router",
]


class ApprovalRequest(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    agent_id: str
    tool: str
    arguments: dict[str, Any] = Field(description="Redacted arguments, safe to display.")
    reason: str
    created_at: float = Field(default_factory=time.time)
    timeout_seconds: float = 300.0


class ApprovalResponse(BaseModel):
    approved: bool
    approver: str | None = None
    comment: str | None = None


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


class ApprovalBroker:
    """In-memory registry of pending approvals, resolved through the HTTP API."""

    def __init__(self) -> None:
        self._pending: dict[str, tuple[ApprovalRequest, asyncio.Future[ApprovalResponse]]] = {}

    def submit(self, request: ApprovalRequest) -> asyncio.Future[ApprovalResponse]:
        future: asyncio.Future[ApprovalResponse] = asyncio.get_running_loop().create_future()
        self._pending[request.id] = (request, future)
        future.add_done_callback(lambda _f: self._pending.pop(request.id, None))
        return future

    def discard(self, request_id: str) -> None:
        """Forget a request (it was decided elsewhere, timed out, or was cancelled)."""
        entry = self._pending.pop(request_id, None)
        if entry is not None and not entry[1].done():
            entry[1].cancel()

    def pending(self) -> list[ApprovalRequest]:
        return [req for req, _ in self._pending.values()]

    def get(self, request_id: str) -> ApprovalRequest | None:
        entry = self._pending.get(request_id)
        return entry[0] if entry else None

    def resolve(self, request_id: str, response: ApprovalResponse) -> bool:
        entry = self._pending.get(request_id)
        if entry is None or entry[1].done():
            return False
        entry[1].get_loop().call_soon_threadsafe(_set_result, entry[1], response)
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
        future = self.broker.submit(request)
        try:
            if self.config.url:
                inline = await self._notify(request)
                if inline is not None:
                    return inline
            return await future
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


def create_approval_router(broker: ApprovalBroker, token: str | None = None) -> APIRouter:
    """FastAPI router exposing pending approvals.

    ``GET /approvals``, ``GET /approvals/{id}``, ``POST /approvals/{id}/approve``
    and ``POST /approvals/{id}/deny``. When ``token`` is set, requests must send
    ``Authorization: Bearer <token>``.
    """
    try:
        from fastapi import APIRouter, Depends, Header, HTTPException
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "run: pip install 'mcp-rbac-gateway[server]' to use the approval API"
        ) from exc

    import hmac

    def check_token(authorization: str | None = Header(default=None)) -> None:
        if token is None:
            return
        expected = f"Bearer {token}"
        if authorization is None or not hmac.compare_digest(authorization, expected):
            raise HTTPException(status_code=401, detail="invalid approval token")

    router = APIRouter(prefix="/approvals", tags=["approvals"], dependencies=[Depends(check_token)])

    @router.get("", response_model=list[ApprovalRequest])
    async def list_pending() -> list[ApprovalRequest]:
        return broker.pending()

    @router.get("/{request_id}", response_model=ApprovalRequest)
    async def get_request(request_id: str) -> ApprovalRequest:
        req = broker.get(request_id)
        if req is None:
            raise HTTPException(status_code=404, detail="no such pending approval")
        return req

    async def _decide(
        request_id: str, approved: bool, body: ApprovalDecisionBody | None
    ) -> dict[str, Any]:
        body = body or ApprovalDecisionBody()
        ok = broker.resolve(
            request_id,
            ApprovalResponse(
                approved=approved, approver=body.approver or "webhook", comment=body.comment
            ),
        )
        if not ok:
            raise HTTPException(status_code=404, detail="no such pending approval")
        return {"id": request_id, "approved": approved}

    @router.post("/{request_id}/approve")
    async def approve(request_id: str, body: ApprovalDecisionBody | None = None) -> dict[str, Any]:
        return await _decide(request_id, True, body)

    @router.post("/{request_id}/deny")
    async def deny(request_id: str, body: ApprovalDecisionBody | None = None) -> dict[str, Any]:
        return await _decide(request_id, False, body)

    return router


def approver_from_config(config: HitlConfig, broker: ApprovalBroker | None = None) -> Approver:
    if config.mode == "auto_approve":
        return AutoApprover(True)
    if config.mode == "auto_deny":
        return AutoApprover(False)
    if config.mode == "webhook":
        return WebhookApprover(config.webhook, broker=broker)
    return CLIApprover()


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
        self, agent_id: str, tool: str, display_arguments: dict[str, Any], reason: str
    ) -> ApprovalOutcome:
        request = ApprovalRequest(
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
