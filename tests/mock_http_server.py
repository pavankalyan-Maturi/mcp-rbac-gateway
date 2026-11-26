"""A mock HTTP MCP server speaking Streamable HTTP (``/mcp``) and legacy SSE (``/sse``)."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from .mock_mcp_server import handle


def create_app() -> FastAPI:
    app = FastAPI()
    app.state.calls = []
    queues: dict[str, asyncio.Queue[dict[str, Any]]] = {}

    def run(msg: dict[str, Any]) -> dict[str, Any] | None:
        if msg.get("method") == "tools/call":
            app.state.calls.append(msg["params"])
        return handle(msg)

    @app.post("/mcp")
    async def mcp(request: Request) -> Response:
        body = json.loads(await request.body())
        items = body if isinstance(body, list) else [body]
        replies = [r for r in (run(m) for m in items) if r is not None]
        headers = {"mcp-session-id": "sess-123"}
        if not replies:
            return Response(status_code=202, headers=headers)
        if request.headers.get("x-mock-mode") == "sse":

            async def stream():
                yield b": keep-alive\n\n"
                for r in replies:
                    yield f"event: message\ndata: {json.dumps(r)}\n\n".encode()

            return StreamingResponse(stream(), media_type="text/event-stream", headers=headers)
        return JSONResponse(replies if isinstance(body, list) else replies[0], headers=headers)

    @app.get("/sse")
    async def sse() -> Response:
        sid = str(len(queues) + 1)
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        queues[sid] = queue

        async def stream():
            yield f"event: endpoint\ndata: /messages?sid={sid}\n\n".encode()
            while True:
                msg = await queue.get()
                yield f"event: message\ndata: {json.dumps(msg)}\n\n".encode()

        return StreamingResponse(stream(), media_type="text/event-stream")

    @app.post("/messages")
    async def messages(request: Request, sid: str) -> Response:
        reply = run(json.loads(await request.body()))
        if reply is not None:
            await queues[sid].put(reply)
        return Response("Accepted", status_code=202)

    return app
