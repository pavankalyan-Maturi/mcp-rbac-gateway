"""SQLite audit trail.

Every tool invocation that passes through the gateway produces one row,
whether it was allowed, blocked by policy, stopped by the scanner, or decided
by a human. Arguments are stored *after* redaction, so the audit database
never becomes a second copy of the secrets it is meant to protect.

Writes run in a worker thread (``asyncio.to_thread``) so the event loop is
never blocked by disk I/O. The database uses WAL mode, which lets
``mcp-rbac-gateway report`` read while a proxy is writing.

With ``audit.writer: batched`` a call does not wait for its row to be
committed: rows go to a bounded queue and one background thread writes them
in batches (``batch_size`` rows or every ``flush_interval_ms``). The queue
blocks when full, so rows are never dropped. Reads through this
:class:`AuditLog` flush first, so they always see earlier writes;
:meth:`AuditLog.close` (and :meth:`Sentinel.close`) flush too. Rows still
queued when the process is killed are lost, which is the tradeoff.

Schema contract
---------------
From 0.3.0 the ``events`` table is a **public, versioned schema**. Its
version is stored in ``PRAGMA user_version`` (:data:`SCHEMA_VERSION`) and the
database is migrated forward when it is opened. Changes are additive:
columns are added, never renamed, retyped or removed, without a major
version bump, and every change is listed in the changelog. A database
written by a newer version than the installed library is refused rather
than silently misread. Use :meth:`AuditLog.query` where you can; reading the
table with your own SQL is supported too.

=========  =======  ==========================================================
version    release  change
=========  =======  ==========================================================
1          0.1.0    initial ``events`` table
2          0.2.0    ``method``, ``protocol_version``, ``client_name``,
                    ``client_version``, ``traceparent``, ``tracestate``, ``meta``
3          0.3.0    ``tenant_id``, ``labels``, ``approval_id``
=========  =======  ==========================================================
"""

from __future__ import annotations

import asyncio
import json
import logging
import queue
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from .config import AuditConfig
from .models import AuditDecision, Finding

__all__ = [
    "SCHEMA_VERSION",
    "AgentStats",
    "AuditEvent",
    "AuditLog",
    "AuditPage",
    "AuditSummary",
    "ToolStats",
    "create_audit_router",
]

SCHEMA_VERSION = 3

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL    NOT NULL,
    agent_id        TEXT    NOT NULL,
    tool            TEXT    NOT NULL,
    decision        TEXT    NOT NULL,
    reason          TEXT    NOT NULL DEFAULT '',
    latency_ms      REAL,
    transport       TEXT    NOT NULL DEFAULT 'python',
    request_id      TEXT,
    session_id      TEXT,
    approver        TEXT,
    arguments       TEXT,
    result          TEXT,
    findings        TEXT,
    redactions      INTEGER NOT NULL DEFAULT 0,
    injection_score REAL    NOT NULL DEFAULT 0,
    is_error        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_agent ON events (agent_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_tool ON events (tool, ts);
CREATE INDEX IF NOT EXISTS idx_events_decision ON events (decision, ts);
"""

# Columns added after 0.1.x. Older databases are upgraded in place.
_ADDED_COLUMNS: tuple[tuple[str, str], ...] = (
    ("method", "TEXT NOT NULL DEFAULT 'tools/call'"),
    ("protocol_version", "TEXT"),
    ("client_name", "TEXT"),
    ("client_version", "TEXT"),
    ("traceparent", "TEXT"),
    ("tracestate", "TEXT"),
    ("meta", "TEXT"),
    ("tenant_id", "TEXT"),
    ("labels", "TEXT"),
    ("approval_id", "TEXT"),
)
_ADDED_INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_events_trace ON events (traceparent)",
    "CREATE INDEX IF NOT EXISTS idx_events_method ON events (method, ts)",
    "CREATE INDEX IF NOT EXISTS idx_events_tenant ON events (tenant_id, id)",
    "CREATE INDEX IF NOT EXISTS idx_events_session ON events (session_id, id)",
    "CREATE INDEX IF NOT EXISTS idx_events_request ON events (request_id)",
)


class AuditEvent(BaseModel):
    id: int | None = None
    ts: float = Field(default_factory=time.time)
    agent_id: str
    tool: str
    decision: AuditDecision
    reason: str = ""
    latency_ms: float | None = None
    transport: str = "python"
    request_id: str | None = None
    session_id: str | None = None
    approver: str | None = None
    arguments: Any = None
    result: Any = None
    findings: list[Finding] = Field(default_factory=list)
    injection_score: float = 0.0
    is_error: bool = False
    method: str = "tools/call"
    protocol_version: str | None = None
    client_name: str | None = None
    client_version: str | None = None
    traceparent: str | None = None
    tracestate: str | None = None
    meta: dict[str, Any] | None = Field(
        default=None, description="The request's params._meta, after redaction."
    )
    tenant_id: str | None = None
    labels: dict[str, str] = Field(default_factory=dict)
    approval_id: str | None = Field(
        default=None, description="The approval request this row belongs to, if any."
    )

    @property
    def redactions(self) -> int:
        return sum(1 for f in self.findings if f.kind != "injection")


class AuditPage(BaseModel):
    events: list[AuditEvent]
    next_before_id: int | None = Field(
        default=None, description="Pass as before_id to get the next page; None on the last page."
    )


class ToolStats(BaseModel):
    tool: str
    calls: int
    blocked: int
    avg_latency_ms: float | None
    p95_latency_ms: float | None


class AgentStats(BaseModel):
    agent_id: str
    calls: int
    blocked: int
    approvals: int


class AuditSummary(BaseModel):
    total: int
    by_decision: dict[str, int]
    agents: list[AgentStats]
    tools: list[ToolStats]
    redactions: int
    injections: int
    first_ts: float | None
    last_ts: float | None


def _truncate(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    text = json.dumps(value, default=str, ensure_ascii=False)
    if limit and len(text) > limit:
        return text[:limit] + f"…(+{len(text) - limit} chars)"
    return text


def _percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    k = max(0, min(len(ordered) - 1, round(pct / 100 * (len(ordered) - 1))))
    return round(ordered[k], 2)


logger = logging.getLogger("mcp_rbac_gateway.audit")
_FLUSH = object()  # queue marker: write what you have now

_INSERT = """INSERT INTO events (ts, agent_id, tool, decision, reason, latency_ms,
                   transport, request_id, session_id, approver, arguments, result, findings,
                   redactions, injection_score, is_error, method, protocol_version,
                   client_name, client_version, traceparent, tracestate, meta,
                   tenant_id, labels, approval_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                           ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""


class AuditLog:
    """Append-only audit store backed by SQLite."""

    def __init__(self, path: str | Path = ".sentinel/audit.db", config: AuditConfig | None = None):
        self.config = config or AuditConfig(path=str(path))
        self.path = Path(path)
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False, timeout=10)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            if str(self.path) != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(_SCHEMA)
            self._migrate()
            self._conn.commit()
        self._queue: queue.Queue[Any] | None = None
        self._writer: threading.Thread | None = None
        self._writer_error: BaseException | None = None
        if self.config.writer == "batched":
            self._queue = queue.Queue(maxsize=self.config.queue_size)
            self._writer = threading.Thread(
                target=self._drain, name="mcp-rbac-gateway-audit", daemon=True
            )
            self._writer.start()

    def _migrate(self) -> None:
        version = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
        if version > SCHEMA_VERSION:
            raise RuntimeError(
                f"audit database {self.path} has schema version {version}, but this "
                f"mcp-rbac-gateway only knows version {SCHEMA_VERSION}: upgrade the package"
            )
        have = {row[1] for row in self._conn.execute("PRAGMA table_info(events)")}
        for name, ddl in _ADDED_COLUMNS:
            if name not in have:
                self._conn.execute(f"ALTER TABLE events ADD COLUMN {name} {ddl}")
        for sql in _ADDED_INDEXES:
            self._conn.execute(sql)
        if version != SCHEMA_VERSION:
            self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    @property
    def schema_version(self) -> int:
        rows = self._fetch("PRAGMA user_version", [])
        return int(rows[0][0])

    @classmethod
    def from_config(cls, config: AuditConfig) -> AuditLog:
        return cls(config.path, config)

    @contextmanager
    def _cursor(self) -> Iterator[sqlite3.Cursor]:
        with self._lock:
            cur = self._conn.cursor()
            try:
                yield cur
                self._conn.commit()
            finally:
                cur.close()

    # ----------------------------------------------------------------- writes

    def _row(self, event: AuditEvent) -> tuple[Any, ...]:
        limit = self.config.max_payload_chars
        args = _truncate(event.arguments, limit) if self.config.log_arguments else None
        result = _truncate(event.result, limit) if self.config.log_results else None
        findings = json.dumps([f.model_dump(exclude_none=True) for f in event.findings])
        meta = _truncate(event.meta, limit) if event.meta else None
        return (
            event.ts,
            event.agent_id,
            event.tool,
            event.decision.value,
            event.reason,
            event.latency_ms,
            event.transport,
            event.request_id,
            event.session_id,
            event.approver,
            args,
            result,
            findings,
            event.redactions,
            event.injection_score,
            int(event.is_error),
            event.method,
            event.protocol_version,
            event.client_name,
            event.client_version,
            event.traceparent,
            event.tracestate,
            meta,
            event.tenant_id,
            json.dumps(event.labels) if event.labels else None,
            event.approval_id,
        )

    def record_sync(self, event: AuditEvent) -> int:
        """Write one row and return its id.

        With the batched writer the row is queued instead and 0 is returned
        (``event.id`` stays None); it is written within ``flush_interval_ms``.
        """
        row = self._row(event)
        if self._queue is not None:
            if self._writer_error is not None:
                raise RuntimeError("audit writer failed") from self._writer_error
            self._queue.put(row)
            return 0
        with self._cursor() as cur:
            cur.execute(_INSERT, row)
            row_id = cur.lastrowid
        event.id = row_id
        return int(row_id or 0)

    async def record(self, event: AuditEvent) -> int:
        if self._queue is not None and not self._queue.full():
            return self.record_sync(event)  # a non-blocking put: no thread hop needed
        return await asyncio.to_thread(self.record_sync, event)

    def flush(self) -> None:
        """Wait until every queued row is written (a no-op for the sync writer)."""
        if self._queue is not None and self._writer is not None and self._writer.is_alive():
            self._queue.put(_FLUSH)  # wakes the writer instead of waiting out the interval
            self._queue.join()
        if self._writer_error is not None:
            raise RuntimeError("audit writer failed") from self._writer_error

    def _drain(self) -> None:
        """Writer thread: one transaction per batch of up to ``batch_size`` rows."""
        assert self._queue is not None
        q = self._queue
        interval = self.config.flush_interval_ms / 1000
        stop = False
        while not stop:
            batch: list[tuple[Any, ...]] = []
            taken = 0
            deadline: float | None = None  # set once the first row arrives
            while len(batch) < self.config.batch_size:
                try:
                    if deadline is None:
                        item = q.get()
                    else:
                        item = q.get(timeout=max(deadline - time.monotonic(), 0.0))
                except queue.Empty:
                    break
                taken += 1
                if item is None:
                    stop = True
                    break
                if item is _FLUSH:
                    break
                batch.append(item)
                if deadline is None:
                    deadline = time.monotonic() + interval
            try:
                if batch:
                    with self._cursor() as cur:
                        cur.executemany(_INSERT, batch)
            except BaseException as exc:  # pragma: no cover - disk full, db closed
                self._writer_error = exc
                logger.exception("audit writer failed; %d row(s) lost", len(batch))
            finally:
                for _ in range(taken):
                    q.task_done()

    # ------------------------------------------------------------------ reads

    def query(
        self,
        *,
        agent_id: str | None = None,
        tool: str | None = None,
        decision: AuditDecision | str | None = None,
        since: float | None = None,
        blocked_only: bool = False,
        limit: int = 100,
        method: str | None = None,
        trace_id: str | None = None,
        session_id: str | None = None,
        tenant_id: str | None = None,
        request_id: str | None = None,
        before_id: int | None = None,
    ) -> list[AuditEvent]:
        """Most recent events first (by row id), filtered by every argument given.

        ``trace_id`` matches the W3C trace id inside ``traceparent``.
        ``before_id`` returns only rows with a smaller id: pass the last id of
        one page to get the next. Keyset pagination stays stable while new
        rows are written, unlike an offset.
        """
        sql, params = self._where(
            agent_id=agent_id,
            tool=tool,
            decision=decision,
            since=since,
            blocked_only=blocked_only,
            method=method,
            trace_id=trace_id,
            session_id=session_id,
            tenant_id=tenant_id,
            request_id=request_id,
            before_id=before_id,
        )
        rows = self._fetch(f"SELECT * FROM events {sql} ORDER BY id DESC LIMIT ?", [*params, limit])
        return [self._to_event(r) for r in rows]

    def page(self, *, limit: int = 100, **filters: Any) -> AuditPage:
        """:meth:`query` plus the cursor for the next page."""
        events = self.query(limit=limit, **filters)
        next_id = events[-1].id if len(events) == limit and events else None
        return AuditPage(events=events, next_before_id=next_id)

    def summary(
        self,
        *,
        since: float | None = None,
        agent_id: str | None = None,
        tenant_id: str | None = None,
    ) -> AuditSummary:
        where, params = self._where(agent_id=agent_id, since=since, tenant_id=tenant_id)
        rows = self._fetch(
            f"SELECT agent_id, tool, decision, latency_ms, redactions, injection_score, ts "
            f"FROM events {where}",
            params,
        )
        by_decision: dict[str, int] = {}
        agents: dict[str, AgentStats] = {}
        tool_latency: dict[str, list[float]] = {}
        tool_calls: dict[str, list[int]] = {}
        redactions = injections = 0
        blocked_values = {d.value for d in AuditDecision if d.is_block}
        requested = AuditDecision.PENDING_APPROVAL.value
        calls = 0
        for r in rows:
            decision = r["decision"]
            by_decision[decision] = by_decision.get(decision, 0) + 1
            if decision == requested:
                continue  # an approval request, not a separate call
            calls += 1
            blocked = decision in blocked_values
            a = agents.setdefault(
                r["agent_id"], AgentStats(agent_id=r["agent_id"], calls=0, blocked=0, approvals=0)
            )
            a.calls += 1
            a.blocked += int(blocked)
            a.approvals += int(decision == AuditDecision.APPROVED.value)
            counts = tool_calls.setdefault(r["tool"], [0, 0])
            counts[0] += 1
            counts[1] += int(blocked)
            if r["latency_ms"] is not None:
                tool_latency.setdefault(r["tool"], []).append(float(r["latency_ms"]))
            redactions += int(r["redactions"])
            injections += int(
                decision == AuditDecision.BLOCKED_INJECTION.value or r["injection_score"] > 0
            )
        tools = [
            ToolStats(
                tool=name,
                calls=c[0],
                blocked=c[1],
                avg_latency_ms=(
                    round(sum(tool_latency[name]) / len(tool_latency[name]), 2)
                    if tool_latency.get(name)
                    else None
                ),
                p95_latency_ms=_percentile(tool_latency.get(name, []), 95),
            )
            for name, c in tool_calls.items()
        ]
        tools.sort(key=lambda t: (-t.calls, t.tool))
        ts_values = [r["ts"] for r in rows]
        return AuditSummary(
            total=calls,
            by_decision=by_decision,
            agents=sorted(agents.values(), key=lambda a: (-a.calls, a.agent_id)),
            tools=tools,
            redactions=redactions,
            injections=injections,
            first_ts=min(ts_values) if ts_values else None,
            last_ts=max(ts_values) if ts_values else None,
        )

    def count(self) -> int:
        rows = self._fetch("SELECT COUNT(*) AS n FROM events", [])
        return int(rows[0]["n"])

    def close(self) -> None:
        """Flush queued rows (batched writer) and close the database."""
        if self._queue is not None and self._writer is not None and self._writer.is_alive():
            self._queue.put(None)
            self._writer.join()
        with self._lock:
            self._conn.close()

    def __enter__(self) -> AuditLog:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -------------------------------------------------------------- internals

    @staticmethod
    def _where(
        *,
        agent_id: str | None = None,
        tool: str | None = None,
        decision: AuditDecision | str | None = None,
        since: float | None = None,
        blocked_only: bool = False,
        method: str | None = None,
        trace_id: str | None = None,
        session_id: str | None = None,
        tenant_id: str | None = None,
        request_id: str | None = None,
        before_id: int | None = None,
    ) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        for column, value in (
            ("agent_id", agent_id),
            ("tool", tool),
            ("method", method),
            ("session_id", session_id),
            ("tenant_id", tenant_id),
            ("request_id", request_id),
        ):
            if value is not None and value != "":
                clauses.append(f"{column} = ?")
                params.append(value)
        if decision:
            clauses.append("decision = ?")
            params.append(decision.value if isinstance(decision, AuditDecision) else decision)
        if since is not None:
            clauses.append("ts >= ?")
            params.append(since)
        if trace_id:
            clauses.append("traceparent LIKE ?")
            params.append(f"__-{trace_id}-%")
        if before_id is not None:
            clauses.append("id < ?")
            params.append(before_id)
        if blocked_only:
            blocked = [d.value for d in AuditDecision if d.is_block]
            clauses.append(f"decision IN ({','.join('?' * len(blocked))})")
            params.extend(blocked)
        return ("WHERE " + " AND ".join(clauses)) if clauses else "", params

    def _fetch(self, sql: str, params: list[Any]) -> list[sqlite3.Row]:
        self.flush()
        with self._cursor() as cur:
            cur.execute(sql, params)
            return list(cur.fetchall())

    @staticmethod
    def _to_event(row: sqlite3.Row) -> AuditEvent:
        def load(text: str | None) -> Any:
            if text is None:
                return None
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return text

        return AuditEvent(
            id=row["id"],
            ts=row["ts"],
            agent_id=row["agent_id"],
            tool=row["tool"],
            decision=AuditDecision(row["decision"]),
            reason=row["reason"],
            latency_ms=row["latency_ms"],
            transport=row["transport"],
            request_id=row["request_id"],
            session_id=row["session_id"],
            approver=row["approver"],
            arguments=load(row["arguments"]),
            result=load(row["result"]),
            findings=[Finding.model_validate(f) for f in (load(row["findings"]) or [])],
            injection_score=row["injection_score"],
            is_error=bool(row["is_error"]),
            method=row["method"],
            protocol_version=row["protocol_version"],
            client_name=row["client_name"],
            client_version=row["client_version"],
            traceparent=row["traceparent"],
            tracestate=row["tracestate"],
            meta=_as_dict(load(row["meta"])),
            tenant_id=row["tenant_id"],
            labels=_as_dict(load(row["labels"])) or {},
            approval_id=row["approval_id"],
        )


def _as_dict(value: Any) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


# --------------------------------------------------------------------- HTTP API


def create_audit_router(
    audit: AuditLog,
    token: str | None = None,
    *,
    require_scope: Callable[[Any], Any] | None = None,
    dependencies: Sequence[Any] = (),
    prefix: str = "/audit",
    allow_unauthenticated: bool = False,
) -> Any:
    """FastAPI router with ``GET /audit``. See :func:`mcp_rbac_gateway.api.create_audit_router`."""
    from .api import create_audit_router as create

    return create(
        audit,
        token,
        require_scope=require_scope,
        dependencies=dependencies,
        prefix=prefix,
        allow_unauthenticated=allow_unauthenticated,
    )
