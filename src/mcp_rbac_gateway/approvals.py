"""Approval requests and where pending ones are kept.

An :class:`ApprovalStore` holds pending approvals so that *any* process can
list and decide them, and a restart does not lose them:

* :class:`MemoryApprovalStore` - in-process (the 0.2 behaviour, the default).
* :class:`SqliteApprovalStore` - a table in a SQLite file (by default the
  audit database), shared by every gateway process on the machine or
  volume. WAL mode, atomic first-writer-wins decisions.

Writing your own store
----------------------
Implement the five methods of :class:`ApprovalStore`. ``resolve`` must be
atomic: of two concurrent calls for the same id, exactly one returns True
(in SQL: ``UPDATE ... SET status = ? WHERE id = ? AND status = 'pending'
AND expires_at > ?`` and check the row count). A store may also define
``async def wait_for_change(request_id, timeout) -> None`` that returns early
when the request may have changed (Postgres ``LISTEN/NOTIFY``, Redis
pub/sub). Waiters then use it instead of polling. The library ships no
Postgres or Redis store, to stay free of those dependencies.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from enum import Enum
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, Field

__all__ = [
    "ApprovalRecord",
    "ApprovalRequest",
    "ApprovalResponse",
    "ApprovalStatus",
    "ApprovalStore",
    "MemoryApprovalStore",
    "SqliteApprovalStore",
]


class ApprovalRequest(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    agent_id: str
    tool: str
    arguments: dict[str, Any] = Field(description="Redacted arguments, safe to display.")
    reason: str
    created_at: float = Field(default_factory=time.time)
    timeout_seconds: float = 300.0
    tenant_id: str | None = None
    session_id: str | None = None
    request_id: str | None = Field(
        default=None, description="The tool-call id, as on the call's audit rows."
    )
    traceparent: str | None = None
    method: str = "tools/call"

    @property
    def expires_at(self) -> float:
        return self.created_at + self.timeout_seconds


class ApprovalResponse(BaseModel):
    approved: bool
    approver: str | None = None
    comment: str | None = None


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class ApprovalRecord(BaseModel):
    """A request plus its current state."""

    request: ApprovalRequest
    status: ApprovalStatus = ApprovalStatus.PENDING
    response: ApprovalResponse | None = None
    resolved_at: float | None = None

    def current(self, now: float | None = None) -> ApprovalRecord:
        """This record with ``expired`` applied if its deadline has passed."""
        now = time.time() if now is None else now
        if self.status is ApprovalStatus.PENDING and self.request.expires_at <= now:
            return self.model_copy(update={"status": ApprovalStatus.EXPIRED})
        return self


@runtime_checkable
class ApprovalStore(Protocol):
    def put(self, request: ApprovalRequest) -> None:
        """Store a new pending request."""

    def get(self, request_id: str) -> ApprovalRecord | None:
        """The request and its state (expired once past its deadline), or None."""

    def list_pending(self, scope: str | None = None) -> list[ApprovalRequest]:
        """Pending, unexpired requests, oldest first; ``scope`` filters by ``tenant_id``."""

    def resolve(self, request_id: str, response: ApprovalResponse) -> bool:
        """Decide a pending request. Atomic: only the first caller gets True."""

    def expire(self, now: float | None = None) -> list[str]:
        """Mark pending requests past their deadline as expired; returns their ids."""


def _status_for(response: ApprovalResponse) -> ApprovalStatus:
    return ApprovalStatus.APPROVED if response.approved else ApprovalStatus.DENIED


class MemoryApprovalStore:
    """Pending approvals in a dict. Lost on restart; visible to this process only.

    Decided and expired requests are kept for ``retention_seconds`` (so a late
    second decision gets a clear "already decided"), then dropped.
    """

    def __init__(self, retention_seconds: float = 3600.0) -> None:
        self.retention_seconds = retention_seconds
        self._records: dict[str, ApprovalRecord] = {}
        self._lock = threading.Lock()

    def put(self, request: ApprovalRequest) -> None:
        now = time.time()
        with self._lock:
            for key in [
                k
                for k, r in self._records.items()
                if (r.resolved_at or r.request.expires_at) + self.retention_seconds < now
            ]:
                del self._records[key]
            self._records[request.id] = ApprovalRecord(request=request)

    def get(self, request_id: str) -> ApprovalRecord | None:
        with self._lock:
            record = self._records.get(request_id)
        return record.current() if record else None

    def list_pending(self, scope: str | None = None) -> list[ApprovalRequest]:
        now = time.time()
        with self._lock:
            records = list(self._records.values())
        return [
            r.request
            for r in sorted(records, key=lambda r: r.request.created_at)
            if r.current(now).status is ApprovalStatus.PENDING
            and (scope is None or r.request.tenant_id == scope)
        ]

    def resolve(self, request_id: str, response: ApprovalResponse) -> bool:
        now = time.time()
        with self._lock:
            record = self._records.get(request_id)
            if record is None or record.current(now).status is not ApprovalStatus.PENDING:
                return False
            self._records[request_id] = record.model_copy(
                update={"status": _status_for(response), "response": response, "resolved_at": now}
            )
            return True

    def expire(self, now: float | None = None) -> list[str]:
        now = time.time() if now is None else now
        expired = []
        with self._lock:
            for key, record in self._records.items():
                if record.current(now).status is ApprovalStatus.EXPIRED and (
                    record.status is ApprovalStatus.PENDING
                ):
                    self._records[key] = record.model_copy(
                        update={"status": ApprovalStatus.EXPIRED, "resolved_at": now}
                    )
                    expired.append(key)
        return expired


_SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT,
    session_id  TEXT,
    request_id  TEXT,
    agent_id    TEXT NOT NULL,
    tool        TEXT NOT NULL,
    status      TEXT NOT NULL,
    request     TEXT NOT NULL,
    response    TEXT,
    created_at  REAL NOT NULL,
    expires_at  REAL NOT NULL,
    resolved_at REAL
);
CREATE INDEX IF NOT EXISTS idx_approvals_pending ON approvals (status, tenant_id, created_at);
"""


class SqliteApprovalStore:
    """Pending approvals in a SQLite table, shared by every process using the file.

    Usually the same file as the audit log. Decisions are a single conditional
    ``UPDATE``, so two replicas approving at once cannot both win.
    """

    def __init__(self, path: str | Path = ".sentinel/audit.db") -> None:
        self.path = Path(path)
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            str(self.path), check_same_thread=False, timeout=10, isolation_level=None
        )
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            if str(self.path) != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(_SCHEMA)

    def put(self, request: ApprovalRequest) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO approvals (id, tenant_id, session_id, request_id, agent_id, tool, "
                "status, request, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    request.id,
                    request.tenant_id,
                    request.session_id,
                    request.request_id,
                    request.agent_id,
                    request.tool,
                    ApprovalStatus.PENDING.value,
                    request.model_dump_json(),
                    request.created_at,
                    request.expires_at,
                ),
            )

    def get(self, request_id: str) -> ApprovalRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM approvals WHERE id = ?", (request_id,)
            ).fetchone()
        return self._record(row).current() if row else None

    def list_pending(self, scope: str | None = None) -> list[ApprovalRequest]:
        sql = "SELECT * FROM approvals WHERE status = 'pending' AND expires_at > ?"
        params: list[Any] = [time.time()]
        if scope is not None:
            sql += " AND tenant_id = ?"
            params.append(scope)
        with self._lock:
            rows = self._conn.execute(sql + " ORDER BY created_at", params).fetchall()
        return [ApprovalRequest.model_validate_json(r["request"]) for r in rows]

    def resolve(self, request_id: str, response: ApprovalResponse) -> bool:
        now = time.time()
        with self._lock:
            cur = self._conn.execute(
                "UPDATE approvals SET status = ?, response = ?, resolved_at = ? "
                "WHERE id = ? AND status = 'pending' AND expires_at > ?",
                (_status_for(response).value, response.model_dump_json(), now, request_id, now),
            )
            return cur.rowcount == 1

    def expire(self, now: float | None = None) -> list[str]:
        now = time.time() if now is None else now
        expired: list[str] = []
        with self._lock:
            ids = [
                r["id"]
                for r in self._conn.execute(
                    "SELECT id FROM approvals WHERE status = 'pending' AND expires_at <= ?", (now,)
                ).fetchall()
            ]
            for request_id in ids:
                cur = self._conn.execute(
                    "UPDATE approvals SET status = 'expired', resolved_at = ? "
                    "WHERE id = ? AND status = 'pending'",
                    (now, request_id),
                )
                if cur.rowcount == 1:
                    expired.append(request_id)
        return expired

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @staticmethod
    def _record(row: sqlite3.Row) -> ApprovalRecord:
        response = row["response"]
        return ApprovalRecord(
            request=ApprovalRequest.model_validate_json(row["request"]),
            status=ApprovalStatus(row["status"]),
            response=ApprovalResponse.model_validate(json.loads(response)) if response else None,
            resolved_at=row["resolved_at"],
        )
