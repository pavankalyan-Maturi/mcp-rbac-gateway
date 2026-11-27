"""SQLite audit trail.

Every tool invocation that passes through sentinel produces exactly one row,
whether it was allowed, blocked by policy, stopped by the scanner, or decided
by a human. Arguments are stored *after* redaction, so the audit database
never becomes a second copy of the secrets it is meant to protect.

Writes run in a worker thread (``asyncio.to_thread``) so the event loop is
never blocked by disk I/O. The database uses WAL mode, which lets
``mcp-rbac-gateway report`` read while a proxy is writing.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from .config import AuditConfig
from .models import AuditDecision, Finding

__all__ = ["AgentStats", "AuditEvent", "AuditLog", "AuditSummary", "ToolStats"]

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
)
_ADDED_INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_events_trace ON events (traceparent)",
    "CREATE INDEX IF NOT EXISTS idx_events_method ON events (method, ts)",
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

    @property
    def redactions(self) -> int:
        return sum(1 for f in self.findings if f.kind != "injection")


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

    def _migrate(self) -> None:
        have = {row[1] for row in self._conn.execute("PRAGMA table_info(events)")}
        for name, ddl in _ADDED_COLUMNS:
            if name not in have:
                self._conn.execute(f"ALTER TABLE events ADD COLUMN {name} {ddl}")
        for sql in _ADDED_INDEXES:
            self._conn.execute(sql)

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

    def record_sync(self, event: AuditEvent) -> int:
        limit = self.config.max_payload_chars
        args = _truncate(event.arguments, limit) if self.config.log_arguments else None
        result = _truncate(event.result, limit) if self.config.log_results else None
        findings = json.dumps([f.model_dump(exclude_none=True) for f in event.findings])
        meta = _truncate(event.meta, limit) if event.meta else None
        with self._cursor() as cur:
            cur.execute(
                """INSERT INTO events (ts, agent_id, tool, decision, reason, latency_ms,
                   transport, request_id, session_id, approver, arguments, result, findings,
                   redactions, injection_score, is_error, method, protocol_version,
                   client_name, client_version, traceparent, tracestate, meta)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                           ?, ?, ?, ?, ?, ?, ?)""",
                (
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
                ),
            )
            row_id = cur.lastrowid
        event.id = row_id
        return int(row_id or 0)

    async def record(self, event: AuditEvent) -> int:
        return await asyncio.to_thread(self.record_sync, event)

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
    ) -> list[AuditEvent]:
        """Most recent events first. ``trace_id`` matches the W3C trace id in ``traceparent``."""
        sql, params = self._where(agent_id, tool, decision, since, blocked_only)
        extra: list[str] = []
        if method:
            extra.append("method = ?")
            params.append(method)
        if trace_id:
            extra.append("traceparent LIKE ?")
            params.append(f"__-{trace_id}-%")
        if extra:
            sql = (sql + " AND " if sql else "WHERE ") + " AND ".join(extra)
        rows = self._fetch(
            f"SELECT * FROM events {sql} ORDER BY ts DESC, id DESC LIMIT ?",
            [
                *params,
                limit,
            ],
        )
        return [self._to_event(r) for r in rows]

    def summary(self, *, since: float | None = None, agent_id: str | None = None) -> AuditSummary:
        where, params = self._where(agent_id, None, None, since, False)
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
        for r in rows:
            decision = r["decision"]
            by_decision[decision] = by_decision.get(decision, 0) + 1
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
            total=len(rows),
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
        with self._lock:
            self._conn.close()

    def __enter__(self) -> AuditLog:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -------------------------------------------------------------- internals

    @staticmethod
    def _where(
        agent_id: str | None,
        tool: str | None,
        decision: AuditDecision | str | None,
        since: float | None,
        blocked_only: bool,
    ) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if agent_id:
            clauses.append("agent_id = ?")
            params.append(agent_id)
        if tool:
            clauses.append("tool = ?")
            params.append(tool)
        if decision:
            clauses.append("decision = ?")
            params.append(decision.value if isinstance(decision, AuditDecision) else decision)
        if since is not None:
            clauses.append("ts >= ?")
            params.append(since)
        if blocked_only:
            blocked = [d.value for d in AuditDecision if d.is_block]
            clauses.append(f"decision IN ({','.join('?' * len(blocked))})")
            params.extend(blocked)
        return ("WHERE " + " AND ".join(clauses)) if clauses else "", params

    def _fetch(self, sql: str, params: list[Any]) -> list[sqlite3.Row]:
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
        )


def _as_dict(value: Any) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None
