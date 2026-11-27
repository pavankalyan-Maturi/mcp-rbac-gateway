# Changelog

## 0.2.0 - 2026-11-27

Support for the stateless MCP revision
[2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/changelog).

- **`mcp-rbac-gateway proxy-http`** (`StatelessHttpProxy`): a reverse proxy for stateless
  Streamable HTTP. It needs no `initialize` and no `Mcp-Session-Id`.
  - It checks `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name` against the body before
    forwarding, and answers `400` with `-32020` (HeaderMismatch) or `-32022` (unsupported
    version) when they disagree.
  - It keeps `Mcp-Param-*` headers in step with redacted arguments.
  - It rejects batches, and answers `GET` and `DELETE` with `405`.
- **`_meta` preserved and audited** in stdio and HTTP modes. New audit columns: `method`,
  `protocol_version`, `client_name`, `client_version`, `traceparent`, `tracestate` and
  `meta`. Existing audit databases are upgraded in place.
  `AuditLog.query(method=..., trace_id=...)`.
- **Tasks extension:** a task is tied to the agent that created it, and task results are
  redacted and checked for injection. `tasks/update` input is redacted. Results are audited
  against the original tool.
- **Skills extension:** `skills/list` is filtered per agent. `skills/get` and `skill://`
  resource reads are checked against the new `agents.<name>.skills` rules, and skill content
  is scanned for prompt injection.
- **New config:** `agents.<name>.methods` (allow/deny globs for any non-`tools/call`
  method), `agents.<name>.skills`, and a top-level `tasks` section.
- Locally generated tool errors carry `resultType: "complete"` for 2026-07-28 requests.
- `validate` shows the methods and skills rules.

## 0.1.1 - 2026-11-26

**Breaking: the import and command names changed** to match the PyPI package.

| | 0.1.0 | 0.1.1 |
| --- | --- | --- |
| Install | `pip install mcp-rbac-gateway` | unchanged |
| Python import | `import mcp_sentinel` | `import mcp_rbac_gateway` |
| CLI command | `mcp-sentinel` | `mcp-rbac-gateway` |

The old names clashed with the unrelated `mcp-sentinel-cli` package, which installs a
module and command with the same names. No alias is kept, because an alias would keep the
clash.

To upgrade, replace `mcp_sentinel` with `mcp_rbac_gateway` in imports and `mcp-sentinel`
with `mcp-rbac-gateway` in scripts and MCP client configs.

Also changed:

- The approval webhook payload `type` is now `mcp_rbac_gateway.approval_request`.
- The logger names are now `mcp_rbac_gateway` and `mcp_rbac_gateway.proxy`.
- Error strings returned to agents start with `[mcp-rbac-gateway]`.
- The README shows the full `mcp-rbac-gateway wrap ... --approval-port 8787` command
  in a code block.

Unchanged: the `Sentinel` class, the `sentinel.yaml` default config file and the
audit database format.

## 0.1.0 - 2026-11-26

First release, published to PyPI as `mcp-rbac-gateway`.

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
