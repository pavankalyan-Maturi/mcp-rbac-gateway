"""MCP reverse proxy (stdio, Streamable HTTP, legacy SSE) and the ``@guard`` decorator.

The proxy speaks JSON-RPC 2.0 and only interprets the messages it needs to:

* ``tools/list`` responses are filtered so an agent never even *sees* tools it
  may not call, and tool annotations are cached (``destructiveHint``).
* ``tools/call`` requests are checked by :meth:`Sentinel.check_call`. Blocked
  calls are answered by the proxy itself with an MCP tool error
  (``isError: true``), so the model gets a readable explanation and the
  upstream server never sees the call.
* ``tools/call`` responses are redacted and scanned for prompt injection.
* ``resources/read`` and ``prompts/get`` responses are redacted.

Everything else (initialize, notifications, pings, server-initiated requests
such as sampling) is passed through untouched.
"""

# NOTE: no `from __future__ import annotations` here: FastAPI resolves the
# endpoint annotations defined inside HttpProxy.build_app() at runtime.

import asyncio
import functools
import inspect
import json
import logging
import os
import sys
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, TypeVar, cast
from urllib.parse import urljoin

from .context import CallContext
from .gateway import ResultCheck, Sentinel, ToolBlockedError
from .mcp import (
    HEADER_MISMATCH,
    NAME_SOURCES,
    POLICY_DENIED,
    SUPPORTED_STATELESS_VERSIONS,
    TASK_METHODS,
    UNSUPPORTED_PROTOCOL_VERSION,
    RequestMeta,
    TaskRegistry,
    decode_header_value,
    expected_name,
    header_param_value,
    skill_path,
)
from .models import AuditDecision, CallVerdict

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import FastAPI

__all__ = [
    "BLOCK_PREFIX",
    "HttpProxy",
    "MessageInterceptor",
    "OnBlock",
    "StatelessHttpProxy",
    "StdioProxy",
    "guard",
]

logger = logging.getLogger("mcp_rbac_gateway.proxy")

BLOCK_PREFIX = "[mcp-rbac-gateway]"
OnBlock = Literal["raise", "return"]
F = TypeVar("F", bound=Callable[..., Any])

JSON = dict[str, Any]


def _key(msg_id: Any) -> str:
    return json.dumps(msg_id, sort_keys=True)


def tool_error_result(text: str, *, modern: bool = False) -> JSON:
    """An MCP ``CallToolResult`` with ``isError``; ``modern`` adds 2026-07-28 ``resultType``."""
    result: JSON = {"content": [{"type": "text", "text": text}], "isError": True}
    if modern:
        result["resultType"] = "complete"
    return result


@dataclass
class _PendingCall:
    verdict: CallVerdict
    started: float
    meta: RequestMeta = field(default_factory=RequestMeta)
    kind: Literal["tool", "task", "skill_content"] = "tool"
    task_id: str | None = None


@dataclass
class Intercepted:
    """Result of inspecting a client->server message."""

    forward: Any | None = None  # message to send upstream
    respond: JSON | None = None  # message to send straight back to the client


_TERMINAL_TASK_STATES = frozenset({"completed", "failed", "cancelled"})


@dataclass
class MessageInterceptor:
    """Transport-agnostic JSON-RPC inspection for one MCP session (or one stateless request).

    ``tasks`` is shared across interceptors so that a task created in one
    stateless HTTP request can be polled in the next.
    """

    sentinel: Sentinel
    agent_id: str | None = None
    transport: str = "stdio"
    session_id: str | None = None
    tasks: TaskRegistry | None = None
    _calls: dict[str, _PendingCall] = field(default_factory=dict)
    _lists: set[str] = field(default_factory=set)
    _skill_lists: set[str] = field(default_factory=set)
    _redact_only: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        if self.tasks is None:
            self.tasks = self.sentinel.tasks

    @property
    def agent(self) -> str:
        return self.sentinel.agent_or_default(self.agent_id)

    # ---------------------------------------------------------- client side

    async def on_client_message(self, msg: Any) -> Intercepted:
        if not isinstance(msg, dict) or "method" not in msg or "id" not in msg:
            return Intercepted(forward=msg)  # notifications, responses, junk
        method = str(msg.get("method"))
        raw_params = msg.get("params")
        params: JSON = raw_params if isinstance(raw_params, dict) else {}
        meta = RequestMeta.from_params(params)
        if method == "tools/call":
            return await self._on_tool_call(msg, params, meta)
        if method in TASK_METHODS:
            return await self._on_task_request(msg, method, params, meta)
        if method in ("skills/get", "resources/read", "resources/directory/read"):
            uri = str(params.get("uri", ""))
            path = skill_path(uri)
            if path is not None:
                return await self._on_skill_read(msg, method, path, meta)

        decision = self.sentinel.policy.evaluate_method(self.agent, method)
        if not decision.allowed:
            verdict = CallVerdict(
                agent_id=self.agent,
                tool=method,
                method=method,
                decision=AuditDecision.BLOCKED_POLICY,
                reason=f"{decision.reason} ({decision.rule})",
                arguments={},
            )
            return await self._refuse(msg, verdict, meta, time.perf_counter())
        key = _key(msg["id"])
        if method == "tools/list":
            self._lists.add(key)
        elif method == "skills/list":
            self._skill_lists.add(key)
        elif method in ("resources/read", "prompts/get"):
            self._redact_only.add(key)
        return Intercepted(forward=msg)

    async def _on_tool_call(self, msg: JSON, params: JSON, meta: RequestMeta) -> Intercepted:
        tool = str(params.get("name", ""))
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            arguments = {"_": arguments}
        started = time.perf_counter()
        context = CallContext(
            session_id=self.session_id,
            request_id=str(msg["id"]),
            traceparent=meta.traceparent,
        )
        verdict = await self.sentinel.check_call(self.agent, tool, arguments, context=context)
        if not verdict.allowed:
            await self._record(verdict, started, msg["id"], meta)
            logger.info("blocked %s for %s: %s", tool, verdict.agent_id, verdict.reason)
            text = f"{BLOCK_PREFIX} Tool call blocked ({verdict.decision.value}): {verdict.reason}"
            return Intercepted(
                respond={
                    "jsonrpc": "2.0",
                    "id": msg["id"],
                    "result": tool_error_result(text, modern=meta.is_stateless),
                }
            )
        self._calls[_key(msg["id"])] = _PendingCall(verdict, started, meta)
        # Only `arguments` is rewritten; `_meta` (clientInfo, traceparent ...) and
        # every other field reach the server exactly as the client sent them.
        forwarded = dict(msg)
        forwarded["params"] = {**params, "arguments": verdict.arguments}
        return Intercepted(forward=forwarded)

    async def _on_task_request(
        self, msg: JSON, method: str, params: JSON, meta: RequestMeta
    ) -> Intercepted:
        started = time.perf_counter()
        task_id = str(params.get("taskId", ""))
        assert self.tasks is not None
        record = self.tasks.get(task_id)
        target = record.tool if record else f"task:{task_id}"
        scan = params.get("inputResponses") if method == "tasks/update" else None
        verdict = self.sentinel.check_method(self.agent, method, target, scan=scan)
        if verdict.allowed and self.sentinel.config.tasks.bind_to_agent:
            if record is None or record.agent_id != verdict.agent_id:
                # Same answer for "unknown" and "someone else's": don't leak which ids exist.
                verdict = verdict.model_copy(
                    update={
                        "decision": AuditDecision.BLOCKED_POLICY,
                        "reason": f"task '{task_id}' was not created by agent "
                        f"'{verdict.agent_id}' through this gateway (tasks.bind_to_agent)",
                    }
                )
                await self._record(verdict, started, msg["id"], meta)
                return Intercepted(
                    respond=_error(msg["id"], -32602, f"Unknown or expired taskId '{task_id}'")
                )
        if not verdict.allowed:
            return await self._refuse(msg, verdict, meta, started)
        forwarded = msg
        if scan is not None:
            forwarded = {
                **msg,
                "params": {**params, "inputResponses": verdict.arguments.get("input", scan)},
            }
        self._calls[_key(msg["id"])] = _PendingCall(
            verdict, started, meta, kind="task", task_id=task_id
        )
        return Intercepted(forward=forwarded)

    async def _on_skill_read(
        self, msg: JSON, method: str, path: str, meta: RequestMeta
    ) -> Intercepted:
        started = time.perf_counter()
        verdict = self.sentinel.check_method(
            self.agent, method, f"skill:{path}" if path else "skill:", skill=path
        )
        if not verdict.allowed:
            return await self._refuse(msg, verdict, meta, started)
        if method == "resources/directory/read":
            self._redact_only.add(_key(msg["id"]))
        else:
            self._calls[_key(msg["id"])] = _PendingCall(
                verdict, started, meta, kind="skill_content"
            )
        return Intercepted(forward=msg)

    async def _refuse(
        self, msg: JSON, verdict: CallVerdict, meta: RequestMeta, started: float
    ) -> Intercepted:
        await self._record(verdict, started, msg["id"], meta)
        logger.info("blocked %s for %s: %s", verdict.method, verdict.agent_id, verdict.reason)
        text = (
            f"{BLOCK_PREFIX} {verdict.method} blocked ({verdict.decision.value}): {verdict.reason}"
        )
        return Intercepted(respond=_error(msg["id"], POLICY_DENIED, text))

    async def _record(
        self, verdict: CallVerdict, started: float, request_id: Any, meta: RequestMeta, **kw: Any
    ) -> None:
        await self.sentinel.record(
            verdict,
            latency_ms=(time.perf_counter() - started) * 1000,
            transport=self.transport,
            request_id=request_id,
            session_id=self.session_id,
            meta=meta,
            **kw,
        )

    # ---------------------------------------------------------- server side

    async def on_server_message(self, msg: Any) -> Any:
        if not isinstance(msg, dict):
            return msg
        if "method" in msg:
            if msg.get("method") == "notifications/tasks" and isinstance(msg.get("params"), dict):
                return {**msg, "params": self._filter_task(msg["params"])[0]}
            return msg  # other notifications and server->client requests
        if "id" not in msg:
            return msg
        key = _key(msg["id"])
        if key in self._lists:
            self._lists.discard(key)
            return self._filter_tool_list(msg)
        if key in self._skill_lists:
            self._skill_lists.discard(key)
            return self._filter_skill_list(msg)
        if key in self._redact_only:
            self._redact_only.discard(key)
            if isinstance(msg.get("result"), dict):
                scan = self.sentinel.scanner.redact(msg["result"], direction="output")
                return {**msg, "result": scan.payload}
            return msg
        pending = self._calls.pop(key, None)
        if pending is None:
            return msg
        if pending.kind == "task":
            return await self._finish_task_request(msg, pending)
        if pending.kind == "skill_content":
            return await self._finish_skill_read(msg, pending)
        return await self._finish_call(msg, pending)

    def _filter_tool_list(self, msg: JSON) -> JSON:
        result = msg.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            return msg
        tools = result["tools"]
        self.sentinel.register_tools(tools)
        visible = self.sentinel.visible_tools(self.agent, tools)
        hidden = len(tools) - len(visible)
        if hidden:
            logger.info("hid %d tool(s) from agent %s", hidden, self.agent)
        return {**msg, "result": {**result, "tools": visible}}

    def _filter_skill_list(self, msg: JSON) -> JSON:
        result = msg.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("skills"), list):
            return msg
        skills = result["skills"]
        visible = self.sentinel.visible_skills(self.agent, skills)
        if len(visible) != len(skills):
            logger.info("hid %d skill(s) from agent %s", len(skills) - len(visible), self.agent)
        redacted = self.sentinel.scanner.redact({**result, "skills": visible}, direction="output")
        return {**msg, "result": redacted.payload}

    def _filter_task(self, task: JSON) -> tuple[JSON, ResultCheck]:
        """Redact and injection-check a Task object (``tasks/get`` result or notification)."""
        check = self.sentinel.check_result(task)
        payload = check.payload if isinstance(check.payload, dict) else task
        if check.blocked:
            text = f"{BLOCK_PREFIX} Task output withheld: {check.reason}"
            payload = {**payload, "statusMessage": text}
            if "result" in payload:
                payload["result"] = tool_error_result(text, modern=True)
            if "inputRequests" in payload:
                # An injected elicitation must not reach the user either.
                payload = {k: v for k, v in payload.items() if k != "inputRequests"}
                payload["status"] = "failed"
                payload["error"] = {"code": POLICY_DENIED, "message": text}
        return payload, check

    async def _finish_call(self, msg: JSON, pending: _PendingCall) -> JSON:
        verdict = pending.verdict
        if "error" in msg:
            err = msg.get("error") or {}
            await self._record(
                verdict,
                pending.started,
                msg["id"],
                pending.meta,
                decision=AuditDecision.ERROR,
                reason=f"upstream error {err.get('code')}: {err.get('message')}",
                is_error=True,
            )
            return msg
        result = msg.get("result")
        if isinstance(result, dict) and result.get("resultType") == "task":
            return await self._task_created(msg, result, pending)
        if isinstance(result, dict) and isinstance(result.get("task"), dict):
            # 2025-11-25 CreateTaskResult: the handle is nested under "task".
            nested = result["task"]
            if isinstance(nested.get("taskId"), str):
                assert self.tasks is not None
                self.tasks.add(nested["taskId"], verdict.agent_id, verdict.tool, nested.get("ttl"))
        check = self.sentinel.check_result(result)
        if check.blocked:
            await self._record(
                verdict,
                pending.started,
                msg["id"],
                pending.meta,
                decision=AuditDecision.BLOCKED_INJECTION,
                reason=check.reason,
                result_check=check,
            )
            text = f"{BLOCK_PREFIX} Tool output withheld: {check.reason}"
            modern = pending.meta.is_stateless or (
                isinstance(result, dict) and "resultType" in result
            )
            return {**msg, "result": tool_error_result(text, modern=modern)}
        is_error = isinstance(result, dict) and bool(result.get("isError"))
        await self._record(
            verdict,
            pending.started,
            msg["id"],
            pending.meta,
            result=check.payload,
            result_check=check,
            is_error=is_error,
        )
        return {**msg, "result": check.payload}

    async def _task_created(self, msg: JSON, handle: JSON, pending: _PendingCall) -> JSON:
        """``tools/call`` answered with ``resultType: "task"`` (tasks extension)."""
        verdict = pending.verdict
        task_id = handle.get("taskId")
        payload, check = self._filter_task(handle)
        if isinstance(task_id, str):
            assert self.tasks is not None
            self.tasks.add(task_id, verdict.agent_id, verdict.tool, handle.get("ttlMs"))
        await self._record(
            verdict,
            pending.started,
            msg["id"],
            pending.meta,
            reason=f"{verdict.reason}; task {task_id} created ({handle.get('status')})",
            result=payload,
            result_check=check,
        )
        return {**msg, "result": payload}

    async def _finish_task_request(self, msg: JSON, pending: _PendingCall) -> JSON:
        verdict = pending.verdict
        method = verdict.method
        result = msg.get("result")
        if "error" in msg or not isinstance(result, dict):
            err = msg.get("error") or {}
            await self._record(
                verdict,
                pending.started,
                msg["id"],
                pending.meta,
                decision=AuditDecision.ERROR,
                reason=f"upstream error {err.get('code')}: {err.get('message')}",
                is_error=True,
            )
            return msg
        if method == "tasks/result":
            # The original tool's result, delivered late: same checks as a tool result.
            return await self._finish_call(msg, pending)
        if method != "tasks/get":
            await self._record(verdict, pending.started, msg["id"], pending.meta)
            return msg
        payload, check = self._filter_task(result)
        status = payload.get("status")
        if check.blocked:
            await self._record(
                verdict,
                pending.started,
                msg["id"],
                pending.meta,
                decision=AuditDecision.BLOCKED_INJECTION,
                reason=check.reason,
                result_check=check,
            )
        elif status in _TERMINAL_TASK_STATES or check.findings:
            # Polls of a running task are not audited one by one; the final
            # state (and anything the scanner changed) is.
            inner = payload.get("result")
            is_error = status == "failed" or (
                isinstance(inner, dict) and bool(inner.get("isError"))
            )
            await self._record(
                verdict,
                pending.started,
                msg["id"],
                pending.meta,
                reason=f"task {pending.task_id} {status}",
                result=payload,
                result_check=check,
                is_error=is_error,
            )
        return {**msg, "result": payload}

    async def _finish_skill_read(self, msg: JSON, pending: _PendingCall) -> JSON:
        verdict = pending.verdict
        if "error" in msg:
            return msg
        check = self.sentinel.check_result(msg.get("result"))
        if check.blocked:
            await self._record(
                verdict,
                pending.started,
                msg["id"],
                pending.meta,
                decision=AuditDecision.BLOCKED_INJECTION,
                reason=check.reason,
                result_check=check,
            )
            text = f"{BLOCK_PREFIX} Skill content withheld: {check.reason}"
            return _error(msg["id"], POLICY_DENIED, text)
        await self._record(verdict, pending.started, msg["id"], pending.meta, result_check=check)
        return {**msg, "result": check.payload}


def _error(msg_id: Any, code: int, message: str) -> JSON:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


# =========================================================================
# stdio
# =========================================================================


class StdioProxy:
    """Spawn an MCP server as a subprocess and proxy newline-delimited JSON-RPC."""

    def __init__(
        self,
        sentinel: Sentinel,
        command: list[str],
        *,
        agent_id: str | None = None,
        env: Mapping[str, str] | None = None,
        cwd: str | None = None,
    ) -> None:
        if not command:
            raise ValueError("upstream command is empty")
        self.sentinel = sentinel
        self.command = command
        self.env = {**os.environ, **(env or {})}
        self.cwd = cwd
        self.interceptor = MessageInterceptor(sentinel, agent_id=agent_id, transport="stdio")
        self._write_lock = asyncio.Lock()
        self.process: asyncio.subprocess.Process | None = None

    async def run(
        self,
        client_reader: asyncio.StreamReader | None = None,
        client_write: Callable[[bytes], Awaitable[None]] | None = None,
    ) -> int:
        """Run until the client closes stdin or the upstream exits. Returns the exit code."""
        reader = client_reader or await _stdin_reader()
        write = client_write or _stdout_writer()
        self.process = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=None,  # inherit: server logs go to our stderr
            env=self.env,
            cwd=self.cwd,
            limit=2**24,
        )
        proc = self.process
        assert proc.stdin is not None and proc.stdout is not None
        upstream_in = proc.stdin
        upstream_out = proc.stdout
        tasks: set[asyncio.Task[None]] = set()

        async def to_client(msg: Any) -> None:
            data = (json.dumps(msg, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
            async with self._write_lock:
                await write(data)

        async def to_upstream(msg: Any) -> None:
            upstream_in.write(
                (json.dumps(msg, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
            )
            await upstream_in.drain()

        async def handle_client(msg: Any) -> None:
            for item in msg if isinstance(msg, list) else [msg]:
                try:
                    outcome = await self.interceptor.on_client_message(item)
                except Exception as exc:  # never let one bad call kill the proxy
                    logger.exception("error while checking client message")
                    if isinstance(item, dict) and "id" in item:
                        await to_client(_internal_error(item["id"], exc))
                    continue
                if outcome.respond is not None:
                    await to_client(outcome.respond)
                if outcome.forward is not None:
                    await to_upstream(outcome.forward)

        async def pump_client() -> None:
            while True:
                line = await reader.readline()
                if not line:
                    break
                if not line.strip():
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    upstream_in.write(line)  # not ours to judge
                    await upstream_in.drain()
                    continue
                is_call = isinstance(msg, dict) and msg.get("method") == "tools/call"
                if is_call:
                    # Run concurrently: an approval prompt must not stall pings etc.
                    task = asyncio.create_task(handle_client(msg))
                    tasks.add(task)
                    task.add_done_callback(tasks.discard)
                else:
                    await handle_client(msg)
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            upstream_in.close()

        async def pump_server() -> None:
            while True:
                line = await upstream_out.readline()
                if not line:
                    break
                if not line.strip():
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    logger.warning("dropping non-JSON line from upstream stdout")
                    continue
                if isinstance(msg, list):
                    out = [await self.interceptor.on_server_message(m) for m in msg]
                    await to_client(out)
                else:
                    await to_client(await self.interceptor.on_server_message(msg))

        client_task = asyncio.create_task(pump_client())
        server_task = asyncio.create_task(pump_server())
        done, _ = await asyncio.wait(
            {client_task, server_task}, return_when=asyncio.FIRST_COMPLETED
        )
        if client_task in done:
            # Client hung up: give the server a moment to flush and exit.
            try:
                await asyncio.wait_for(server_task, timeout=5)
            except asyncio.TimeoutError:
                server_task.cancel()
        else:
            client_task.cancel()
        try:
            code = await asyncio.wait_for(proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            proc.terminate()
            code = await proc.wait()
        for t in (client_task, server_task):
            if not t.done():
                t.cancel()
        return code


def _internal_error(msg_id: Any, exc: BaseException) -> JSON:
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": -32603, "message": f"{BLOCK_PREFIX} internal error: {exc}"},
    }


async def _stdin_reader() -> asyncio.StreamReader:
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=2**24)
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)
    return reader


def _stdout_writer() -> Callable[[bytes], Awaitable[None]]:
    out = sys.stdout.buffer

    async def write(data: bytes) -> None:
        out.write(data)
        out.flush()

    return write


# =========================================================================
# HTTP: Streamable HTTP + legacy SSE
# =========================================================================

_HOP_BY_HOP = {
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "accept-encoding",
    "x-sentinel-token",
    "x-sentinel-agent",
}


def _parse_sse(buffer: str) -> tuple[list[tuple[str, str]], str]:
    """Split complete SSE events off ``buffer``. Returns ``([(event, data)], rest)``."""
    events: list[tuple[str, str]] = []
    buffer = buffer.replace("\r\n", "\n")
    while "\n\n" in buffer:
        raw, buffer = buffer.split("\n\n", 1)
        event, data_lines = "message", []
        for line in raw.split("\n"):
            if line.startswith(":"):
                continue
            name, _, value = line.partition(":")
            value = value[1:] if value.startswith(" ") else value
            if name == "event":
                event = value
            elif name == "data":
                data_lines.append(value)
        if data_lines or event != "message":
            events.append((event, "\n".join(data_lines)))
    return events, buffer


def _sse(event: str, data: str) -> bytes:
    lines = "".join(f"data: {line}\n" for line in data.split("\n"))
    return f"event: {event}\n{lines}\n".encode()


class HttpProxy:
    """A FastAPI app that fronts an HTTP MCP server.

    * **Streamable HTTP** (MCP 2025-03-26+): ``POST/GET/DELETE {path}`` are
      forwarded to ``upstream_url``; JSON and ``text/event-stream`` responses
      are both inspected.
    * **Legacy HTTP+SSE** (MCP 2024-11-05): ``GET /sse`` opens the upstream
      stream and rewrites its ``endpoint`` event so the client posts to
      ``/messages`` on the proxy instead.

    Agent identity comes from the ``X-Sentinel-Agent`` header. If any agent in
    the config defines ``token_env``, callers must also prove their identity
    with ``X-Sentinel-Token``; the header alone is then never trusted.
    """

    def __init__(
        self,
        sentinel: Sentinel,
        upstream_url: str,
        *,
        path: str = "/mcp",
        default_agent: str | None = None,
        headers: Mapping[str, str] | None = None,
        approval_token: str | None = None,
        timeout: float = 300.0,
        transport: Any = None,
    ) -> None:
        self.sentinel = sentinel
        self.upstream_url = upstream_url
        self.path = path
        self.default_agent = default_agent
        self.headers = dict(headers or {})
        self.approval_token = approval_token
        self.timeout = timeout
        self._transport = transport  # httpx transport override, used by tests
        self._sse_sessions: dict[str, _SseSession] = {}
        self._tokens = {
            os.environ[a.token_env]: name
            for name, a in sentinel.config.agents.items()
            if a.token_env and os.environ.get(a.token_env)
        }
        self._auth_required = any(a.token_env for a in sentinel.config.agents.values())

    # ----------------------------------------------------------- identity

    def identify(self, headers: Mapping[str, str]) -> str | None:
        """Resolve the calling agent. Raises ``PermissionError`` on a bad token."""
        if self._auth_required:
            import hmac

            token = headers.get("x-sentinel-token")
            if token:
                for known, name in self._tokens.items():
                    if hmac.compare_digest(token, known):
                        return name
                raise PermissionError("invalid X-Sentinel-Token")
            # No token: fall back to the default (usually least-privileged) agent.
            return self.default_agent
        return headers.get("x-sentinel-agent") or self.default_agent

    def _client(self) -> Any:
        import httpx

        return httpx.AsyncClient(timeout=self.timeout, transport=self._transport)

    def _forward_headers(self, incoming: Mapping[str, str]) -> dict[str, str]:
        out = {k: v for k, v in incoming.items() if k.lower() not in _HOP_BY_HOP}
        out.update(self.headers)
        return out

    # ---------------------------------------------------------------- app

    def build_app(self) -> "FastAPI":
        try:
            from fastapi import FastAPI, Request, Response
            from fastapi.responses import JSONResponse, StreamingResponse
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "run: pip install 'mcp-rbac-gateway[server]' to use the HTTP proxy"
            ) from exc

        from .hitl import create_approval_router

        app = FastAPI(title="mcp-rbac-gateway", version=_version())
        app.include_router(create_approval_router(self.sentinel.broker, self.approval_token))
        proxy = self

        @app.get("/healthz")
        async def healthz() -> dict[str, str]:
            return {"status": "ok"}

        @app.post(self.path)
        async def post_mcp(request: Request) -> Response:
            try:
                agent = proxy.identify(request.headers)
            except PermissionError as exc:
                return JSONResponse({"error": str(exc)}, status_code=401)
            body = await request.body()
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": "Parse error"},
                    },
                    status_code=400,
                )
            session = request.headers.get("mcp-session-id")
            interceptor = MessageInterceptor(
                proxy.sentinel, agent_id=agent, transport="http", session_id=session
            )
            items = payload if isinstance(payload, list) else [payload]
            forward: list[Any] = []
            local: list[JSON] = []
            for item in items:
                outcome = await interceptor.on_client_message(item)
                if outcome.respond is not None:
                    local.append(outcome.respond)
                if outcome.forward is not None:
                    forward.append(outcome.forward)

            if not forward:
                # Every request was answered by the gateway itself.
                return JSONResponse(local if isinstance(payload, list) else local[0])

            upstream_body = forward if isinstance(payload, list) else forward[0]
            client = proxy._client()
            upstream_req = client.build_request(
                "POST",
                proxy.upstream_url,
                content=json.dumps(upstream_body).encode(),
                headers={
                    **proxy._forward_headers(request.headers),
                    "content-type": "application/json",
                },
            )
            upstream = await client.send(upstream_req, stream=True)
            passthrough = {
                k: v
                for k, v in upstream.headers.items()
                if k.lower() in {"mcp-session-id", "mcp-protocol-version"}
            }
            ctype = upstream.headers.get("content-type", "")

            if ctype.startswith("text/event-stream"):

                async def stream() -> AsyncIterator[bytes]:
                    try:
                        for msg in local:
                            yield _sse("message", json.dumps(msg))
                        async for chunk in _filter_sse(upstream, interceptor):
                            yield chunk
                    finally:
                        await upstream.aclose()
                        await client.aclose()

                return StreamingResponse(
                    stream(),
                    status_code=upstream.status_code,
                    media_type="text/event-stream",
                    headers=passthrough,
                )

            raw = await upstream.aread()
            await upstream.aclose()
            await client.aclose()
            if not raw or not ctype.startswith("application/json"):
                if local:
                    return JSONResponse(
                        local if isinstance(payload, list) else local[0], headers=passthrough
                    )
                return Response(
                    raw,
                    status_code=upstream.status_code,
                    headers=passthrough,
                    media_type=ctype or None,
                )
            data = json.loads(raw)
            if isinstance(data, list):
                filtered: Any = [await interceptor.on_server_message(m) for m in data] + local
            else:
                filtered = await interceptor.on_server_message(data)
                if local:
                    filtered = [filtered, *local]
            return JSONResponse(filtered, status_code=upstream.status_code, headers=passthrough)

        @app.get(self.path)
        async def get_mcp(request: Request) -> Response:
            # Server-initiated stream: no tool calls originate here, but
            # responses may still arrive on it, so it is scanned too.
            try:
                agent = proxy.identify(request.headers)
            except PermissionError as exc:
                return JSONResponse({"error": str(exc)}, status_code=401)
            interceptor = MessageInterceptor(proxy.sentinel, agent_id=agent, transport="http")
            client = proxy._client()
            req = client.build_request(
                "GET", proxy.upstream_url, headers=proxy._forward_headers(request.headers)
            )
            upstream = await client.send(req, stream=True)
            if not upstream.headers.get("content-type", "").startswith("text/event-stream"):
                raw = await upstream.aread()
                await upstream.aclose()
                await client.aclose()
                return Response(raw, status_code=upstream.status_code)

            async def stream() -> AsyncIterator[bytes]:
                try:
                    async for chunk in _filter_sse(upstream, interceptor):
                        yield chunk
                finally:
                    await upstream.aclose()
                    await client.aclose()

            return StreamingResponse(stream(), media_type="text/event-stream")

        @app.delete(self.path)
        async def delete_mcp(request: Request) -> Response:
            async with proxy._client() as client:
                upstream = await client.delete(
                    proxy.upstream_url, headers=proxy._forward_headers(request.headers)
                )
            return Response(upstream.content, status_code=upstream.status_code)

        # ------------------------------------------------ legacy HTTP+SSE

        @app.get("/sse")
        async def legacy_sse(request: Request) -> Response:
            try:
                agent = proxy.identify(request.headers)
            except PermissionError as exc:
                return JSONResponse({"error": str(exc)}, status_code=401)
            session = _SseSession(
                MessageInterceptor(proxy.sentinel, agent_id=agent, transport="sse")
            )
            client = proxy._client()
            req = client.build_request(
                "GET", proxy.upstream_url, headers=proxy._forward_headers(request.headers)
            )
            upstream = await client.send(req, stream=True)

            async def stream() -> AsyncIterator[bytes]:
                buffer = ""
                try:
                    async for text in upstream.aiter_text():
                        buffer += text
                        events, buffer = _parse_sse(buffer)
                        for event, data in events:
                            if event == "endpoint":
                                session.upstream_endpoint = urljoin(proxy.upstream_url, data)
                                session.interceptor.session_id = session.id
                                proxy._sse_sessions[session.id] = session
                                yield _sse("endpoint", f"/messages?session_id={session.id}")
                                continue
                            yield await _filter_event(event, data, session.interceptor)
                finally:
                    proxy._sse_sessions.pop(session.id, None)
                    await upstream.aclose()
                    await client.aclose()

            async def merged() -> AsyncIterator[bytes]:
                # Interleave upstream events with responses the gateway generates itself.
                queue: asyncio.Queue[bytes | None] = asyncio.Queue()

                async def pump() -> None:
                    try:
                        async for chunk in stream():
                            await queue.put(chunk)
                    finally:
                        await queue.put(None)

                session.push = lambda msg: queue.put_nowait(_sse("message", json.dumps(msg)))
                task = asyncio.create_task(pump())
                try:
                    while True:
                        chunk = await queue.get()
                        if chunk is None:
                            break
                        yield chunk
                finally:
                    task.cancel()

            return StreamingResponse(merged(), media_type="text/event-stream")

        @app.post("/messages")
        async def legacy_messages(request: Request, session_id: str) -> Response:
            session = proxy._sse_sessions.get(session_id)
            if session is None or session.upstream_endpoint is None:
                return JSONResponse({"error": "unknown session"}, status_code=404)
            msg = json.loads(await request.body())
            outcome = await session.interceptor.on_client_message(msg)
            if outcome.respond is not None and session.push is not None:
                session.push(outcome.respond)
            if outcome.forward is not None:
                async with proxy._client() as client:
                    upstream = await client.post(
                        session.upstream_endpoint,
                        json=outcome.forward,
                        headers=proxy._forward_headers(
                            {
                                k: v
                                for k, v in request.headers.items()
                                if k.lower() != "content-type"
                            }
                        ),
                    )
                return Response(upstream.content, status_code=upstream.status_code)
            return Response("Accepted", status_code=202)

        return app


class StatelessHttpProxy(HttpProxy):
    """Reverse proxy for the stateless Streamable HTTP transport (MCP 2026-07-28).

    Every ``POST {path}`` is one self-contained JSON-RPC message. There is no
    ``initialize`` handshake and no ``Mcp-Session-Id``: the protocol version,
    client info and trace context travel in each request's ``params._meta``.

    Before anything is forwarded the proxy checks the routing headers the
    spec requires (``MCP-Protocol-Version``, ``Mcp-Method`` and, where the
    method needs it, ``Mcp-Name``) against the body and answers ``400`` with
    JSON-RPC error ``-32020`` (HeaderMismatch) when they disagree. Policy is
    then decided on the body, so a load balancer that routes on headers and
    the gateway that enforces policy on the body can never be told different
    stories.

    ``GET`` and ``DELETE`` on the endpoint return ``405``, as the spec asks of
    servers that support only this revision. Use :class:`HttpProxy` (``serve``)
    for clients and servers on 2025-era protocol versions.
    """

    def __init__(
        self,
        sentinel: Sentinel,
        upstream_url: str,
        *,
        supported_versions: tuple[str, ...] = SUPPORTED_STATELESS_VERSIONS,
        **kwargs: Any,
    ) -> None:
        super().__init__(sentinel, upstream_url, **kwargs)
        self.supported_versions = supported_versions

    def check_headers(self, headers: Mapping[str, str], msg: JSON) -> JSON | None:
        """Validate routing headers against the body. Returns an error body or None."""
        msg_id = msg.get("id")
        method = str(msg.get("method"))
        raw_params = msg.get("params")
        params: JSON = raw_params if isinstance(raw_params, dict) else {}

        version = headers.get("mcp-protocol-version")
        if version not in self.supported_versions:
            what = f"'{version}'" if version else "missing"
            return _error_data(
                msg_id,
                UNSUPPORTED_PROTOCOL_VERSION,
                f"Unsupported protocol version: MCP-Protocol-Version header is {what}",
                {"supported": list(self.supported_versions), "requested": version},
            )
        meta = RequestMeta.from_params(params)
        if "id" in msg:
            if meta.protocol_version is None:
                return _error(
                    msg_id,
                    -32602,
                    "Invalid params: _meta['io.modelcontextprotocol/protocolVersion'] is required",
                )
            if meta.protocol_version != version:
                return _mismatch(msg_id, "MCP-Protocol-Version", version, meta.protocol_version)

        header_method = headers.get("mcp-method")
        if header_method is None:
            return _error(msg_id, HEADER_MISMATCH, "Header mismatch: Mcp-Method header is required")
        if header_method != method:
            return _mismatch(msg_id, "Mcp-Method", header_method, method)

        expected = expected_name(method, params)
        if method in NAME_SOURCES:
            header_name = headers.get("mcp-name")
            if header_name is None:
                return _error(
                    msg_id,
                    HEADER_MISMATCH,
                    f"Header mismatch: Mcp-Name header is required for {method}",
                )
            try:
                decoded = decode_header_value(header_name)
            except ValueError as exc:
                return _error(msg_id, HEADER_MISMATCH, f"Header mismatch: {exc}")
            if decoded != expected:
                return _mismatch(msg_id, "Mcp-Name", decoded, expected)
        return None

    def _stateless_headers(
        self, incoming: Mapping[str, str], original: JSON, forwarded: JSON
    ) -> dict[str, str]:
        out = {
            k: v
            for k, v in self._forward_headers(incoming).items()
            if k.lower() not in {"mcp-session-id", "last-event-id", "content-type"}
        }
        out["content-type"] = "application/json"
        if original.get("method") != "tools/call":
            return out
        params = forwarded.get("params") or {}
        before = (original.get("params") or {}).get("arguments")
        after = params.get("arguments")
        mapping = self.sentinel.tool_param_headers.get(str(params.get("name", "")))
        if not mapping or before == after or not isinstance(after, dict):
            return out
        # Redaction changed an argument the client mirrored into a header: keep
        # header and body consistent, or the server would reject the request.
        lowered = {k.lower(): k for k in out}
        for header, path in mapping.items():
            value = header_param_value(after, path)
            existing = lowered.get(header)
            if existing is not None:
                del out[existing]
            if value is not None:
                out[header] = value
        return out

    def build_app(self) -> "FastAPI":
        try:
            from fastapi import FastAPI, Request, Response
            from fastapi.responses import JSONResponse, StreamingResponse
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "run: pip install 'mcp-rbac-gateway[server]' to use the HTTP proxy"
            ) from exc

        from .hitl import create_approval_router

        app = FastAPI(title="mcp-rbac-gateway (stateless)", version=_version())
        app.include_router(create_approval_router(self.sentinel.broker, self.approval_token))
        proxy = self

        def bad_request(body: JSON) -> Response:
            return JSONResponse(body, status_code=400)

        @app.get("/healthz")
        async def healthz() -> dict[str, str]:
            return {"status": "ok", "protocol": ",".join(proxy.supported_versions)}

        @app.post(self.path)
        async def post_mcp(request: Request) -> Response:
            try:
                agent = proxy.identify(request.headers)
            except PermissionError as exc:
                return JSONResponse({"error": str(exc)}, status_code=401)
            try:
                msg = json.loads(await request.body())
            except json.JSONDecodeError:
                return bad_request(_error(None, -32700, "Parse error"))
            if isinstance(msg, list):
                return bad_request(
                    _error(None, -32600, "Invalid Request: send one JSON-RPC message per POST")
                )
            if not isinstance(msg, dict) or not isinstance(msg.get("method"), str):
                return bad_request(
                    _error(
                        msg.get("id") if isinstance(msg, dict) else None,
                        -32600,
                        "Invalid Request: clients may only POST requests and notifications",
                    )
                )
            problem = proxy.check_headers(request.headers, msg)
            if problem is not None:
                logger.info("rejected %s: %s", msg.get("method"), problem["error"]["message"])
                return bad_request(problem)

            interceptor = MessageInterceptor(
                proxy.sentinel, agent_id=agent, transport="http-stateless"
            )
            try:
                outcome = await interceptor.on_client_message(msg)
            except Exception as exc:
                logger.exception("error while checking client message")
                return JSONResponse(_internal_error(msg.get("id"), exc))
            if outcome.respond is not None:
                return JSONResponse(outcome.respond)
            forwarded = cast(JSON, outcome.forward)

            import httpx

            long_lived = msg.get("method") == "subscriptions/listen"
            client = httpx.AsyncClient(
                timeout=httpx.Timeout(proxy.timeout, read=None if long_lived else proxy.timeout),
                transport=proxy._transport,
            )
            upstream_req = client.build_request(
                "POST",
                proxy.upstream_url,
                content=json.dumps(forwarded).encode(),
                headers=proxy._stateless_headers(request.headers, msg, forwarded),
            )
            upstream = await client.send(upstream_req, stream=True)
            ctype = upstream.headers.get("content-type", "")
            passthrough = {
                k: v for k, v in upstream.headers.items() if k.lower() in {"x-accel-buffering"}
            }

            if ctype.startswith("text/event-stream"):

                async def stream() -> AsyncIterator[bytes]:
                    try:
                        async for chunk in _filter_sse(upstream, interceptor):
                            yield chunk
                    finally:
                        await upstream.aclose()
                        await client.aclose()

                passthrough.setdefault("x-accel-buffering", "no")
                return StreamingResponse(
                    stream(),
                    status_code=upstream.status_code,
                    media_type="text/event-stream",
                    headers=passthrough,
                )

            raw = await upstream.aread()
            await upstream.aclose()
            await client.aclose()
            if not raw or not ctype.startswith("application/json"):
                return Response(raw, status_code=upstream.status_code, media_type=ctype or None)
            data = json.loads(raw)
            filtered = await interceptor.on_server_message(data)
            return JSONResponse(filtered, status_code=upstream.status_code)

        @app.api_route(self.path, methods=["GET", "DELETE"])
        async def not_allowed() -> Response:
            return Response(status_code=405, headers={"allow": "POST"})

        return app


def _error_data(msg_id: Any, code: int, message: str, data: Any) -> JSON:
    body = _error(msg_id, code, message)
    body["error"]["data"] = data
    return body


def _mismatch(msg_id: Any, header: str, header_value: Any, body_value: Any) -> JSON:
    return _error(
        msg_id,
        HEADER_MISMATCH,
        f"Header mismatch: {header} header value '{header_value}' does not match "
        f"body value '{body_value}'",
    )


@dataclass
class _SseSession:
    interceptor: MessageInterceptor
    id: str = field(default_factory=lambda: os.urandom(16).hex())
    upstream_endpoint: str | None = None
    push: Callable[[JSON], None] | None = None


async def _filter_event(event: str, data: str, interceptor: MessageInterceptor) -> bytes:
    if event != "message" or not data:
        return _sse(event, data)
    try:
        msg = json.loads(data)
    except json.JSONDecodeError:
        return _sse(event, data)
    if isinstance(msg, list):
        out: Any = [await interceptor.on_server_message(m) for m in msg]
    else:
        out = await interceptor.on_server_message(msg)
    return _sse(event, json.dumps(out, ensure_ascii=False))


async def _filter_sse(upstream: Any, interceptor: MessageInterceptor) -> AsyncIterator[bytes]:
    buffer = ""
    async for text in upstream.aiter_text():
        buffer += text
        events, buffer = _parse_sse(buffer)
        for event, data in events:
            yield await _filter_event(event, data, interceptor)


def _version() -> str:
    from . import __version__

    return __version__


# =========================================================================
# Decorator
# =========================================================================

_SKIP_PARAMS = {"self", "cls"}


def guard(
    sentinel: Sentinel,
    *,
    tool: str | None = None,
    agent_id: str | None = None,
    on_block: OnBlock = "raise",
    context: CallContext | None = None,
) -> Callable[[F], F]:
    """Protect a Python tool function with the full gateway pipeline.

    Works on ``async def`` and plain functions. Place it *under* framework
    decorators such as LangChain's ``@tool`` so the framework sees the guarded
    function::

        @tool
        @guard(sentinel, on_block="return")
        async def delete_file(path: str) -> str: ...

    Args:
        tool: Tool name used for policy matching (defaults to ``fn.__name__``).
        agent_id: Fixed agent identity. When omitted, the identity bound with
            :func:`mcp_rbac_gateway.agent_context` is used, then ``default_agent``.
        on_block: ``"raise"`` raises :class:`ToolBlockedError`; ``"return"``
            returns a ``"[mcp-rbac-gateway] ..."`` string the LLM can read and
            recover from, which is usually what agent frameworks want.
        context: Fixed :class:`CallContext` for every call. When omitted, the
            context bound with :func:`mcp_rbac_gateway.call_context` at call
            time is used.
    """

    def decorator(fn: F) -> F:
        name = tool or fn.__name__
        sig = inspect.signature(fn)

        def split(
            args: tuple[Any, ...], kwargs: dict[str, Any]
        ) -> tuple[dict[str, Any], dict[str, Any]]:
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            hidden: dict[str, Any] = {}
            visible: dict[str, Any] = {}
            for pname, value in bound.arguments.items():
                kind = sig.parameters[pname].kind
                if pname in _SKIP_PARAMS:
                    hidden[pname] = value
                elif kind is inspect.Parameter.VAR_KEYWORD:
                    visible.update(value)
                elif kind is inspect.Parameter.VAR_POSITIONAL:
                    visible[pname] = list(value)
                else:
                    visible[pname] = value
            return hidden, visible

        def rebuild(
            hidden: dict[str, Any], safe: dict[str, Any]
        ) -> tuple[list[Any], dict[str, Any]]:
            merged = {**safe, **hidden}
            args: list[Any] = []
            kwargs: dict[str, Any] = {}
            consumed: set[str] = set()
            for pname, param in sig.parameters.items():
                if param.kind is inspect.Parameter.VAR_KEYWORD:
                    continue
                if pname not in merged:
                    continue
                consumed.add(pname)
                if param.kind is inspect.Parameter.POSITIONAL_ONLY:
                    args.append(merged[pname])
                elif param.kind is inspect.Parameter.VAR_POSITIONAL:
                    args.extend(merged[pname])
                else:
                    kwargs[pname] = merged[pname]
            for extra, value in merged.items():
                if extra not in consumed:
                    kwargs[extra] = value
            return args, kwargs

        def blocked(exc: ToolBlockedError) -> str:
            if on_block == "raise":
                raise exc
            return f"{BLOCK_PREFIX} Tool '{name}' blocked ({exc.decision.value}): {exc.reason}"

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                hidden, visible = split(args, kwargs)

                async def run(safe: dict[str, Any]) -> Any:
                    a, k = rebuild(hidden, safe)
                    return await fn(*a, **k)

                try:
                    return await sentinel.call(
                        name, visible, run, agent_id=agent_id, context=context
                    )
                except ToolBlockedError as exc:
                    return blocked(exc)

            return cast(F, async_wrapper)

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            hidden, visible = split(args, kwargs)

            def run(safe: dict[str, Any]) -> Any:
                a, k = rebuild(hidden, safe)
                return fn(*a, **k)

            try:
                return sentinel.call_sync(name, visible, run, agent_id=agent_id, context=context)
            except ToolBlockedError as exc:
                return blocked(exc)

        return cast(F, sync_wrapper)

    return decorator
