# Changelog

## 0.1.0 - 2026-11-26

First release, published to PyPI as `mcp-sentinel-gateway`.

- Policy & RBAC engine: per-agent allow/deny globs, inheritance, argument
  constraints (`pattern`, `deny_pattern`, `max_length`, `allowed_values`, `required`).
- Security scanner: 16 built-in secret/PII detectors, custom patterns, and
  weighted prompt-injection heuristics with `warn`/`block` actions.
- Human-in-the-loop gate: CLI (`/dev/tty`), webhook, and FastAPI approval API;
  rules on tool names, argument regexes, and MCP `destructiveHint` annotations.
- MCP proxy: stdio (`mcp-sentinel wrap`), Streamable HTTP and legacy SSE
  (`mcp-sentinel serve`), with per-agent `tools/list` filtering.
- `@guard` decorator for LangGraph, LangChain, FastAPI or any Python tool.
- SQLite audit trail and `mcp-sentinel report` Rich dashboard.
