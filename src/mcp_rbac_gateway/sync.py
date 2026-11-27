"""Running the async engine from sync code.

:func:`run_sync` is what :meth:`Sentinel.call_sync`, :meth:`Sentinel.check_call_sync`
and ``@guard`` on a plain ``def`` use:

* **No event loop in this thread** (plain scripts, ``asyncio.to_thread``
  workers, Flask/Django views, LangGraph sync nodes): the coroutine runs
  with :func:`asyncio.run`.
* **An event loop is already running in this thread** (sync code called from
  inside ``async def``): ``asyncio.run`` would fail, so the coroutine runs on
  a fresh loop in a worker thread, with the caller's contextvars copied over
  (agent and call context included). The calling thread, *and the loop it
  is running*, wait until it finishes. An approval that must be answered by
  an HTTP endpoint served by that same loop would therefore never arrive: in
  async code use the async API (``await sentinel.call(...)``), or resolve
  approvals from another process through a shared
  :class:`~mcp_rbac_gateway.hitl.SqliteApprovalStore`.
"""

from __future__ import annotations

import asyncio
import contextvars
from collections.abc import Callable, Coroutine
from concurrent.futures import ThreadPoolExecutor
from typing import Any, TypeVar

__all__ = ["run_sync"]

T = TypeVar("T")

_executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="mcp-rbac-gateway")


def run_sync(factory: Callable[[], Coroutine[Any, Any, T]]) -> T:
    """Run the coroutine made by ``factory`` to completion and return its result."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(factory())
    ctx = contextvars.copy_context()
    return _executor.submit(ctx.run, lambda: asyncio.run(factory())).result()
