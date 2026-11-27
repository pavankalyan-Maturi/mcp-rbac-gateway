"""A mock MCP server for the stateless Streamable HTTP transport (2026-07-28).

Like a real server, it validates the routing headers against the body, so
the tests can prove the proxy keeps them consistent after rewriting a body.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from mcp_rbac_gateway.mcp import decode_header_value, expected_name, param_header_map

from .mock_mcp_server import TOOLS, handle

PARAM_HEADERS = {t["name"]: param_header_map(t.get("inputSchema")) for t in TOOLS}


def mismatch(mid: Any, message: str) -> Response:
    body = {"jsonrpc": "2.0", "id": mid, "error": {"code": -32020, "message": message}}
    return JSONResponse(body, status_code=400)


def create_app() -> FastAPI:
    app = FastAPI()
    app.state.received = []  # (headers, body) for every POST

    @app.post("/mcp")
    async def mcp(request: Request) -> Response:
        msg = json.loads(await request.body())
        headers = {k.lower(): v for k, v in request.headers.items()}
        app.state.received.append((headers, msg))
        method = msg.get("method")
        params = msg.get("params") or {}
        if headers.get("mcp-method") != method:
            return mismatch(msg.get("id"), "Mcp-Method")
        name = expected_name(method, params)
        if name is not None and decode_header_value(headers.get("mcp-name", "")) != name:
            return mismatch(msg.get("id"), "Mcp-Name")
        if method == "tools/call":
            args = params.get("arguments") or {}
            for header, path in PARAM_HEADERS.get(params.get("name"), {}).items():
                if header in headers and decode_header_value(headers[header]) != args.get(path[0]):
                    return mismatch(msg.get("id"), f"{header} does not match body")
        reply = handle(msg)
        if reply is None:
            return Response(status_code=202)
        if headers.get("x-mock-mode") == "sse":

            async def stream():
                note = {"jsonrpc": "2.0", "method": "notifications/progress", "params": {}}
                yield f"event: message\ndata: {json.dumps(note)}\n\n".encode()
                yield f"event: message\ndata: {json.dumps(reply)}\n\n".encode()

            return StreamingResponse(stream(), media_type="text/event-stream")
        return JSONResponse(reply)

    @app.get("/mcp")
    async def get_mcp() -> Response:
        return Response(status_code=405)

    return app
