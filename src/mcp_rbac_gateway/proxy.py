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
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine, Mapping
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, TypeVar, cast
from urllib.parse import urljoin

from .gateway import Sentinel, ToolBlockedError
from .models import AuditDecision, CallVerdict

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import FastAPI

__all__ = [
    "BLOCK_PREFIX",
    "HttpProxy",
    "MessageInterceptor",
    "OnBlock",
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


def tool_error_result(text: str) -> JSON:
    return {"content": [{"type": "text", "text": text}], "isError": True}


@dataclass
class _PendingCall:
    verdict: CallVerdict
    started: float


@dataclass
class Intercepted:
    """Result of inspecting a client->server message."""

    forward: Any | None = None  # message to send upstream
    respond: JSON | None = None  # message to send straight back to the client


@dataclass
class MessageInterceptor:
    """Transport-agnostic JSON-RPC inspection for one MCP session."""

    sentinel: Sentinel
    agent_id: str | None = None
    transport: str = "stdio"
    session_id: str | None = None
    _calls: dict[str, _PendingCall] = field(default_factory=dict)
    _lists: set[str] = field(default_factory=set)
    _redact_only: set[str] = field(default_factory=set)

    @property
    def agent(self) -> str:
        return self.sentinel.agent_or_default(self.agent_id)

    # ---------------------------------------------------------- client side

    async def on_client_message(self, msg: Any) -> Intercepted:
        if not isinstance(msg, dict) or "method" not in msg or "id" not in msg:
            return Intercepted(forward=msg)  # notifications, responses, junk
        method = msg.get("method")
        key = _key(msg["id"])
        if method == "tools/list":
            self._lists.add(key)
            return Intercepted(forward=msg)
        if method in ("resources/read", "prompts/get"):
            self._redact_only.add(key)
            return Intercepted(forward=msg)
        if method != "tools/call":
            return Intercepted(forward=msg)

        params = msg.get("params") or {}
        tool = str(params.get("name", ""))
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            arguments = {"_": arguments}
        started = time.perf_counter()
        verdict = await self.sentinel.check_call(self.agent, tool, arguments)
        if not verdict.allowed:
            await self.sentinel.record(
                verdict,
                latency_ms=(time.perf_counter() - started) * 1000,
                transport=self.transport,
                request_id=msg["id"],
                session_id=self.session_id,
            )
            logger.info("blocked %s for %s: %s", tool, verdict.agent_id, verdict.reason)
            text = f"{BLOCK_PREFIX} Tool call blocked ({verdict.decision.value}): {verdict.reason}"
            return Intercepted(
                respond={"jsonrpc": "2.0", "id": msg["id"], "result": tool_error_result(text)}
            )
        self._calls[key] = _PendingCall(verdict, started)
        forwarded = dict(msg)
        forwarded["params"] = {**params, "arguments": verdict.arguments}
        return Intercepted(forward=forwarded)

    # ---------------------------------------------------------- server side

    async def on_server_message(self, msg: Any) -> Any:
        if not isinstance(msg, dict) or "method" in msg or "id" not in msg:
            return msg  # notifications and server->client requests
        key = _key(msg["id"])
        if key in self._lists:
            self._lists.discard(key)
            return self._filter_tool_list(msg)
        if key in self._redact_only:
            self._redact_only.discard(key)
            if isinstance(msg.get("result"), dict):
                scan = self.sentinel.scanner.redact(msg["result"], direction="output")
                return {**msg, "result": scan.payload}
            return msg
        pending = self._calls.pop(key, None)
        if pending is None:
            return msg
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

    async def _finish_call(self, msg: JSON, pending: _PendingCall) -> JSON:
        verdict = pending.verdict
        if "error" in msg:
            err = msg.get("error") or {}
            await self.sentinel.record(
                verdict,
                decision=AuditDecision.ERROR,
                reason=f"upstream error {err.get('code')}: {err.get('message')}",
                latency_ms=(time.perf_counter() - pending.started) * 1000,
                transport=self.transport,
                request_id=msg["id"],
                session_id=self.session_id,
                is_error=True,
            )
            return msg
        result = msg.get("result")
        check = self.sentinel.check_result(result)
        latency = (time.perf_counter() - pending.started) * 1000
        if check.blocked:
            await self.sentinel.record(
                verdict,
                decision=AuditDecision.BLOCKED_INJECTION,
                reason=check.reason,
                latency_ms=latency,
                transport=self.transport,
                request_id=msg["id"],
                session_id=self.session_id,
                result_check=check,
            )
            text = f"{BLOCK_PREFIX} Tool output withheld: {check.reason}"
            return {**msg, "result": tool_error_result(text)}
        is_error = isinstance(result, dict) and bool(result.get("isError"))
        await self.sentinel.record(
            verdict,
            latency_ms=latency,
            transport=self.transport,
            request_id=msg["id"],
            session_id=self.session_id,
            result=check.payload,
            result_check=check,
            is_error=is_error,
        )
        return {**msg, "result": check.payload}


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
                # Every request was answered by sentinel itself.
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
                # Interleave upstream events with responses sentinel generates itself.
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
_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="mcp-rbac-gateway")


def guard(
    sentinel: Sentinel,
    *,
    tool: str | None = None,
    agent_id: str | None = None,
    on_block: OnBlock = "raise",
) -> Callable[[F], F]:
    """Protect a Python tool function with the full sentinel pipeline.

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
                    return await sentinel.call(name, visible, run, agent_id=agent_id)
                except ToolBlockedError as exc:
                    return blocked(exc)

            return cast(F, async_wrapper)

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            hidden, visible = split(args, kwargs)

            async def run(safe: dict[str, Any]) -> Any:
                a, k = rebuild(hidden, safe)
                return await asyncio.to_thread(fn, *a, **k)

            async def main() -> Any:
                return await sentinel.call(name, visible, run, agent_id=agent_id)

            try:
                return _run_sync(main)
            except ToolBlockedError as exc:
                return blocked(exc)

        return cast(F, sync_wrapper)

    return decorator


def _run_sync(factory: Callable[[], Coroutine[Any, Any, Any]]) -> Any:
    """Run a coroutine from sync code, even if this thread already has a loop."""
    import contextvars

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(factory())
    ctx = contextvars.copy_context()
    future: Future[Any] = _executor.submit(ctx.run, asyncio.run, factory())
    return future.result()
