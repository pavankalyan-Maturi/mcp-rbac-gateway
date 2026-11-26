"""FastAPI service exposing guarded tools, a LangGraph agent, and the approval API.

Run it:

    pip install "mcp-sentinel[server,langgraph]"
    uvicorn examples.fastapi_app:create_app --factory --port 8000

Try it:

    # Direct tool calls, as different agents
    curl -s localhost:8000/tools/read_file -H 'X-Agent-Id: support-bot' \
         -H 'content-type: application/json' -d '{"path": "docs/ops/keys.md"}'
    curl -s localhost:8000/tools/delete_file -H 'X-Agent-Id: support-bot' \
         -H 'content-type: application/json' -d '{"path": "docs/refunds.md"}'

    # Run the ops agent; it will pause on delete_file and destructive SQL
    curl -s localhost:8000/agent/run -H 'content-type: application/json' \
         -d '{"agent_id": "ops-agent", "question": "Clean up"}' &
    curl -s localhost:8000/approvals                     # see what is waiting
    curl -s -X POST localhost:8000/approvals/<id>/approve -d '{"approver": "me"}' \
         -H 'content-type: application/json'

    # Dashboard data
    curl -s localhost:8000/audit/summary
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent))
import tools as raw  # noqa: E402
from langgraph_agent import ScriptedModel, build_graph  # noqa: E402

from mcp_sentinel import (  # noqa: E402
    AuditLog,
    Sentinel,
    ToolBlockedError,
    agent_context,
    create_approval_router,
    load_config,
)

HERE = Path(__file__).parent
TOOLS = {
    fn.__name__: fn
    for fn in (
        raw.search_web,
        raw.read_file,
        raw.write_file,
        raw.delete_file,
        raw.lookup_customer,
        raw.run_sql,
    )
}

OPS_SCRIPT = [
    [{"name": "read_file", "args": {"path": "docs/refunds.md"}}],
    [{"name": "delete_file", "args": {"path": "docs/ops/keys.md"}}],  # needs approval
    [{"name": "run_sql", "args": {"query": "DROP TABLE legacy_orders"}}],  # needs approval
]


class RunRequest(BaseModel):
    agent_id: str
    question: str


class RunResponse(BaseModel):
    agent_id: str
    answer: str
    tool_results: list[dict[str, Any]]


def create_app(
    config_path: str | Path = HERE / "sentinel.yaml", audit_path: str | None = None
) -> FastAPI:
    config = load_config(config_path)
    # Approvals are decided over HTTP: webhook mode without a URL means
    # "wait for POST /approvals/{id}/approve|deny".
    config.hitl.mode = "webhook"
    config.hitl.webhook.url = None
    if audit_path:
        config.audit.path = audit_path
    sentinel = Sentinel(config)

    app = FastAPI(title="mcp-sentinel FastAPI example")
    app.state.sentinel = sentinel
    app.include_router(create_approval_router(sentinel.broker))

    @app.post("/tools/{name}")
    async def call_tool(
        name: str, arguments: dict[str, Any], x_agent_id: str = Header(default="guest")
    ) -> dict[str, Any]:
        fn = TOOLS.get(name)
        if fn is None:
            raise HTTPException(404, f"unknown tool {name}")
        try:
            result = await sentinel.call(name, arguments, lambda a: fn(**a), agent_id=x_agent_id)
        except ToolBlockedError as exc:
            raise HTTPException(
                403, {"decision": exc.decision.value, "reason": exc.reason}
            ) from exc
        return {"result": result}

    @app.post("/agent/run", response_model=RunResponse)
    async def run_agent(body: RunRequest) -> RunResponse:
        from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

        graph = build_graph(sentinel, ScriptedModel(script=OPS_SCRIPT))
        with agent_context(body.agent_id):
            state = await graph.ainvoke({"messages": [HumanMessage(body.question)]})
        msgs = state["messages"]
        answer = next((m.content for m in reversed(msgs) if isinstance(m, AIMessage)), "")
        results = [
            {"tool": m.name, "output": m.content} for m in msgs if isinstance(m, ToolMessage)
        ]
        return RunResponse(agent_id=body.agent_id, answer=str(answer), tool_results=results)

    @app.get("/audit/summary")
    async def audit_summary() -> dict[str, Any]:
        log: AuditLog | None = sentinel.audit
        if log is None:
            return {"enabled": False}
        return log.summary().model_dump()

    return app
