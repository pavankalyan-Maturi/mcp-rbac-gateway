# Changelog

## 0.3.0 - unreleased

Changes from an integration review by a production multi-tenant agent platform
(LangGraph, FastAPI, Postgres). Each item removes a workaround that integration needed.
0.2 behaviour stays the default wherever possible; the breaking changes are listed at
the end.

### Request context (tenant, session, tool-call id, trace)

- New `CallContext(session_id, request_id, traceparent, tenant_id, labels)` and
  `with call_context(...)` (a context variable, like `agent_context`; nested blocks merge,
  concurrent tasks never share it). `current_call_context()` reads it.
- `Sentinel.call()`, `@guard`, `check_call()` and `record()` take `context=`. An explicit
  context beats the bound one. It goes on every row a call writes: allowed, blocked,
  injection, error and approval rows.
- When no `traceparent` is given and OpenTelemetry is installed, it is read from the
  current span. OpenTelemetry stays optional.

### Sync API

- `Sentinel.call_sync`, `check_call_sync` and `resume_call_sync`, and `@guard` on plain
  `def` functions, use a new `run_sync` helper: `asyncio.run` when no loop is running;
  inside a running loop, a worker thread with the caller's context variables (never
  `asyncio.run` inside a loop). The guarded function itself runs in the calling thread.
  Approval waits work from the sync path.

### Audit query API and schema

- `AuditLog.query(..., session_id=, tenant_id=, request_id=, before_id=)`, and
  `AuditLog.page(...)` returning an `AuditPage(events, next_before_id)` for keyset
  pagination that stays stable while rows are written. `summary(tenant_id=)`.
- The `events` table is now a **public, versioned schema**: `PRAGMA user_version`
  (`SCHEMA_VERSION = 3`), forward migrations on open, additive changes only. A database
  from a newer version is refused instead of misread. New columns: `tenant_id`, `labels`,
  `approval_id`. 0.1 and 0.2 databases are upgraded in place and keep their rows.
- `create_audit_router(audit, token=None, *, require_scope=None, dependencies=())` serves
  `GET /audit` (filters `agent`, `tool`, `decision`, `method`, `blocked_only`, `since`,
  `session_id`, `request_id`, `tenant_id`, `trace_id`, `limit` ≤ 500, `before_id`). A
  tenant returned by `require_scope` is forced into the query.
- Both routers take `dependencies=[Depends(...)]` so hosts can reuse their own auth.

### Durable, multi-instance approvals

- `ApprovalStore` protocol (`put`, `get`, `list_pending(scope)`, atomic first-writer-wins
  `resolve`, `expire`) with `MemoryApprovalStore` (default, the 0.2 behaviour) and
  `SqliteApprovalStore` (an `approvals` table in the audit database, WAL mode).
  Config: `hitl.store: memory | sqlite`, `hitl.store_path`. Postgres and Redis stores are
  documented as an extension point (with an optional `wait_for_change` notify hook), not
  shipped, so no new dependencies.
- `ApprovalBroker(store=...)` waits by polling the store with backoff, so any replica (or
  a restarted process) can decide a request and the waiter still gets the result.
- `ApprovalRequest` gains `tenant_id`, `session_id`, `request_id`, `traceparent` and
  `method`; `GET /approvals` can be scoped per tenant with `require_scope=`.
- `check_call(..., wait=False)` returns a `pending_approval` verdict with `approval_id`
  instead of waiting. `Sentinel.resume_call(approval_id, response, fn=None)` finishes it
  later with the same audit trail; a second decision raises `ApprovalConflict`.
- The approval request itself is audited (`pending_approval`, with `approval_id`), not
  only the decision. A timeout is recorded as `approval_timeout`.
- New `hitl.mode: api`: wait for the approval API only, with no webhook and no terminal.

### Naming

- Leftover `mcp_sentinel` / "sentinel" wording in docstrings, comments and CLI help now
  says `mcp_rbac_gateway` / "the gateway". No `mcp_sentinel` alias module is shipped: it
  would clash again with the unrelated `mcp-sentinel-cli` package (see 0.1.1).

### Structured denials

- `on_block="result"` on `guard`, `call` and `call_sync` returns a `ToolDenial` (`tool`,
  `decision`, `reason`, `retryable`, `hint`, `request_id`, `approval_id`) for blocks and
  tool errors. `to_text()` is safe to put in a prompt: it never echoes arguments, withheld
  output or exception messages. `retryable` is true only for `approval_timeout` and
  `error`. `ToolBlockedError.denial()` builds one from an exception.

### Policy introspection

- `Sentinel.visible_tools(agent_id, names)` accepts tool names and returns names; tool
  descriptors still work as before.
- `Sentinel.needs_approval(agent_id, tool, args)` returns the approval reason, or None
  when no approval is needed **or the call would be blocked anyway**.
- `mcp-rbac-gateway check-policy CONFIG [-t TOOL]... [-a AGENT]...` prints each agent's
  inheritance chain and effective allow/deny/approval, with a decision column per tool.
  `EffectivePolicy.chain` lists the chain.
- Documented: deny wins along the whole inheritance chain; a child cannot allow what a
  parent denies.

### Performance and docs

- Optional batched audit writer: `audit.writer: batched` (`batch_size`,
  `flush_interval_ms`, `queue_size`). A bounded queue that blocks when full (never drops
  rows) and one writer thread; reads flush first and `close()` flushes. New
  `AuditLog.flush()`. The default stays `sync`.
- `benchmarks/overhead.py` and measured numbers in the README.
- Documented which `hitl.mode` applies when the host mounts the approval router.

### HTTP proxy

- `context_resolver(headers, body) -> CallContext` on `HttpProxy` and
  `StatelessHttpProxy`, called once per request; its tenant, session and labels go on
  every audit row the request writes.
- `agent_resolver(headers) -> agent | None` replaces the `X-Sentinel-Token` lookup (for
  example a role claim of an OAuth bearer token). The token mapping stays the default.
  Both resolvers may be async, and raising `PermissionError` answers `401`.
- New `DualHttpProxy` (CLI: `proxy-http --dual-era`): one endpoint for both protocol
  eras, dispatched on `MCP-Protocol-Version` (stateless path for 2026-07-28, `HttpProxy`
  path otherwise).
- The proxies take `approval_dependencies=` and `allow_unauthenticated_approvals=`.
- `transport=` is documented: pass `httpx.ASGITransport(app=upstream)` to run a proxy in
  front of an in-process ASGI app.

### Breaking changes

- **The approval API fails closed.** `create_approval_router` (and the new
  `create_audit_router`) raise `ValueError` without `token` or `dependencies`, unless
  `allow_unauthenticated=True`. `HttpProxy`/`StatelessHttpProxy.build_app()` no longer
  mount an open `/approvals`: without `approval_token` or `approval_dependencies` it is
  not mounted, and in `hitl.mode` `webhook` or `api` `build_app()` raises. The CLI
  (`wrap --approval-port`, `serve`, `proxy-http`) needs `hitl.webhook.token_env` or
  `--allow-unauthenticated-approvals`. To keep 0.2 behaviour, pass
  `allow_unauthenticated=True` / `allow_unauthenticated_approvals=True`.
- **Deciding an approval twice answers `409`** (was `404`). Unknown ids still answer `404`.
- **Approval requests add audit rows.** A call that needs approval now writes a
  `pending_approval` row before its decision row. `summary()` leaves these rows out of
  its totals; your own SQL on `events` may need `decision != 'pending_approval'`.
- **`AuditLog.query()` orders by `id DESC`** (was `ts DESC, id DESC`), so pagination is
  stable. The order differs only for rows written with out-of-order timestamps.
- **`CallVerdict.allowed`** is true only for `allowed` and `approved`. The new
  `pending_approval` verdict (from `wait=False`) is not allowed; check `verdict.pending`.
- **`@guard` on a sync function runs it in the calling thread**, not in a worker thread of
  the gateway's own executor, so thread-local state (database sessions, Flask/Django
  request locals) works.
- **The default approver name from the approval API is `"api"`** (was `"webhook"`) when
  the request body names none.
- The config error for a non-mapping YAML file reads "config must be a YAML mapping".

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
