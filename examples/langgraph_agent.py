"""A LangGraph agent whose tools are guarded by mcp-sentinel.

Run it:

    pip install "mcp-sentinel[langgraph]"
    python examples/langgraph_agent.py

By default it uses a scripted model, so it runs offline with no API key and the
output is deterministic. Set ``ANTHROPIC_API_KEY`` (and
``pip install langchain-anthropic``) to drive the same graph with Claude.

Then look at what happened:

    mcp-sentinel report -c examples/sentinel.yaml
"""

from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import BaseTool, tool
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode, tools_condition

sys.path.insert(0, str(Path(__file__).parent))
import tools as raw  # noqa: E402

from mcp_sentinel import Sentinel, agent_context, guard  # noqa: E402

HERE = Path(__file__).parent


def build_tools(sentinel: Sentinel) -> list[BaseTool]:
    """Wrap each plain function: @tool (LangChain) on top of @guard (sentinel)."""
    wrapped = []
    for fn in (
        raw.search_web,
        raw.read_file,
        raw.write_file,
        raw.delete_file,
        raw.lookup_customer,
        raw.run_sql,
    ):
        # on_block="return": the model receives a readable refusal instead of a crash.
        wrapped.append(tool(guard(sentinel, on_block="return")(fn)))
    return wrapped


class ScriptedModel(BaseChatModel):
    """A stand-in LLM that replays a fixed list of tool calls, then summarises."""

    script: list[list[dict[str, Any]]]
    step: int = 0

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools: Sequence[Any], **kwargs: Any) -> ScriptedModel:  # type: ignore[override]
        return self

    def _generate(
        self, messages: list[BaseMessage], stop: Any = None, run_manager: Any = None, **kwargs: Any
    ) -> ChatResult:
        if self.step < len(self.script):
            calls = [
                {"name": c["name"], "args": c["args"], "id": f"call_{self.step}_{i}"}
                for i, c in enumerate(self.script[self.step])
            ]
            self.step += 1
            msg = AIMessage(content="", tool_calls=calls)
        else:
            results = [m for m in messages if isinstance(m, ToolMessage)]
            msg = AIMessage(content=f"Done. I made {len(results)} tool calls.")
        return ChatResult(generations=[ChatGeneration(message=msg)])


DEMO_SCRIPT = [
    [{"name": "search_web", "args": {"query": "refund policy"}}],  # injection -> withheld
    [{"name": "lookup_customer", "args": {"customer_id": "42"}}],  # PII -> redacted
    [{"name": "read_file", "args": {"path": "docs/../secrets.txt"}}],  # traversal -> denied
    [{"name": "read_file", "args": {"path": "docs/ops/keys.md"}}],  # secret -> redacted
    [{"name": "run_sql", "args": {"query": "DELETE FROM orders"}}],  # non-SELECT -> denied
    [{"name": "delete_file", "args": {"path": "docs/refunds.md"}}],  # not allowed for role
]


def make_model() -> BaseChatModel:
    if os.environ.get("ANTHROPIC_API_KEY"):
        from langchain_anthropic import ChatAnthropic  # type: ignore[import-not-found]

        return ChatAnthropic(model="claude-sonnet-5-5")
    return ScriptedModel(script=DEMO_SCRIPT)


def build_graph(sentinel: Sentinel, model: BaseChatModel | None = None) -> Any:
    tools = build_tools(sentinel)
    llm = (model or make_model()).bind_tools(tools)

    async def agent(state: MessagesState) -> dict[str, list[BaseMessage]]:
        return {"messages": [await llm.ainvoke(state["messages"])]}

    graph = StateGraph(MessagesState)
    graph.add_node("agent", agent)
    graph.add_node("tools", ToolNode(tools))
    graph.add_edge(START, "agent")
    graph.add_conditional_edges("agent", tools_condition)
    graph.add_edge("tools", "agent")
    return graph.compile()


async def main() -> None:
    sentinel = Sentinel.from_yaml(HERE / "sentinel.yaml")
    graph = build_graph(sentinel)
    question = "A customer (id 42) asks about refunds. Investigate and clean up old docs."
    with agent_context("support-bot"):  # every tool call below runs as this agent
        state = await graph.ainvoke({"messages": [HumanMessage(question)]})

    for msg in state["messages"]:
        if isinstance(msg, ToolMessage):
            print(f"🔧 {msg.name:<16} → {str(msg.content)[:110]}")
        elif isinstance(msg, AIMessage) and msg.content:
            print(f"🤖 {msg.content}")
    sentinel.close()
    print("\nAudit trail: mcp-sentinel report -c examples/sentinel.yaml --since 1h")


if __name__ == "__main__":
    asyncio.run(main())
