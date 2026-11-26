"""Tiny JSON-RPC client for driving the stdio proxy in tests."""

from __future__ import annotations

import asyncio
import itertools
import json
from typing import Any


class StdioClient:
    def __init__(self, proc: asyncio.subprocess.Process) -> None:
        self.proc = proc
        self._ids = itertools.count(1)
        self._pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self._reader = asyncio.create_task(self._read())

    @classmethod
    async def spawn(cls, *cmd: str, env: dict[str, str] | None = None) -> StdioClient:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        return cls(proc)

    async def _read(self) -> None:
        assert self.proc.stdout is not None
        async for line in self.proc.stdout:
            msg = json.loads(line)
            fut = self._pending.pop(msg.get("id"), None)
            if fut is not None and not fut.done():
                fut.set_result(msg)

    async def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        mid = next(self._ids)
        fut: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._pending[mid] = fut
        await self.send({"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}})
        return await asyncio.wait_for(fut, timeout=15)

    async def send(self, msg: Any) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write((json.dumps(msg) + "\n").encode())
        await self.proc.stdin.drain()

    async def call_tool(self, name: str, **arguments: Any) -> dict[str, Any]:
        return await self.request("tools/call", {"name": name, "arguments": arguments})

    async def initialize(self) -> dict[str, Any]:
        resp = await self.request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"},
            },
        )
        await self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return resp

    async def close(self) -> int:
        assert self.proc.stdin is not None
        self.proc.stdin.close()
        code = await asyncio.wait_for(self.proc.wait(), timeout=15)
        self._reader.cancel()
        return code

    async def stderr(self) -> str:
        assert self.proc.stderr is not None
        return (await self.proc.stderr.read()).decode()


def text_of(response: dict[str, Any]) -> str:
    return "".join(c.get("text", "") for c in response["result"]["content"])
