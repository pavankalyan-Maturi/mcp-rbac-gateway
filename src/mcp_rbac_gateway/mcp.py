"""Protocol helpers for MCP revision 2026-07-28 (stateless core).

This module holds the parts of the spec the gateway has to understand to
enforce policy on the stateless transport:

* per-request ``_meta`` (protocol version, client info, W3C trace context),
* the routing headers ``MCP-Protocol-Version``, ``Mcp-Method``, ``Mcp-Name``
  and ``Mcp-Param-*``, including their ``=?base64?...?=`` value encoding,
* the ``io.modelcontextprotocol/tasks`` and ``io.modelcontextprotocol/skills``
  extension methods.

References: https://modelcontextprotocol.io/specification/2026-07-28
"""

from __future__ import annotations

import base64
import binascii
import re
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "HEADER_MISMATCH",
    "LATEST_PROTOCOL_VERSION",
    "NAME_SOURCES",
    "SUPPORTED_STATELESS_VERSIONS",
    "UNSUPPORTED_PROTOCOL_VERSION",
    "RequestMeta",
    "TaskRecord",
    "TaskRegistry",
    "decode_header_value",
    "encode_header_value",
    "expected_name",
    "param_header_map",
    "skill_path",
]

LATEST_PROTOCOL_VERSION = "2026-07-28"
SUPPORTED_STATELESS_VERSIONS: tuple[str, ...] = (LATEST_PROTOCOL_VERSION,)

# JSON-RPC error codes reserved by MCP (2026-07-28).
HEADER_MISMATCH = -32020
MISSING_REQUIRED_CLIENT_CAPABILITY = -32021
UNSUPPORTED_PROTOCOL_VERSION = -32022
# Implementation-defined range (-32000..-32019): a request the gateway refused.
POLICY_DENIED = -32010

META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"

#: Methods whose ``Mcp-Name`` header is required, and the ``params`` field it mirrors.
NAME_SOURCES: dict[str, str] = {
    "tools/call": "name",
    "resources/read": "uri",
    "prompts/get": "name",
    "tasks/get": "taskId",
    "tasks/update": "taskId",
    "tasks/cancel": "taskId",
}

# tasks/result is the 2025-11-25 (experimental core tasks) way to fetch a result.
TASK_METHODS = frozenset({"tasks/get", "tasks/update", "tasks/cancel", "tasks/result"})
SKILL_SCHEME = "skill://"


# --------------------------------------------------------------------- _meta


@dataclass(frozen=True)
class RequestMeta:
    """What the gateway records from a request's ``params._meta``.

    The gateway never trusts these values for identity: ``clientInfo`` is
    self-reported by the client. They are kept for the audit trail and for
    correlating gateway decisions with distributed traces.
    """

    protocol_version: str | None = None
    client_name: str | None = None
    client_version: str | None = None
    traceparent: str | None = None
    tracestate: str | None = None
    raw: dict[str, Any] | None = None

    @classmethod
    def from_params(cls, params: Any) -> RequestMeta:
        meta = params.get("_meta") if isinstance(params, Mapping) else None
        if not isinstance(meta, Mapping) or not meta:
            return cls()
        info = meta.get(META_CLIENT_INFO)
        info = info if isinstance(info, Mapping) else {}
        return cls(
            protocol_version=_str(meta.get(META_PROTOCOL_VERSION)),
            client_name=_str(info.get("name")),
            client_version=_str(info.get("version")),
            traceparent=_str(meta.get("traceparent")),
            tracestate=_str(meta.get("tracestate")),
            raw=dict(meta),
        )

    @property
    def trace_id(self) -> str | None:
        """The 32-hex-digit trace id from a W3C ``traceparent``, if well formed."""
        if not self.traceparent:
            return None
        parts = self.traceparent.split("-")
        if len(parts) == 4 and re.fullmatch(r"[0-9a-f]{32}", parts[1]):
            return parts[1]
        return None

    @property
    def is_stateless(self) -> bool:
        """True for requests that follow the 2026-07-28 per-request ``_meta`` model."""
        return self.protocol_version is not None and self.protocol_version >= "2026-07-28"


def _str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


# ------------------------------------------------------------------ headers

_B64_RE = re.compile(r"^=\?base64\?(.*)\?=$", re.DOTALL)


def decode_header_value(value: str) -> str:
    """Decode an ``Mcp-Name`` / ``Mcp-Param-*`` value (``=?base64?...?=`` form)."""
    match = _B64_RE.match(value)
    if not match:
        return value
    try:
        return base64.b64decode(match.group(1), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise ValueError(f"invalid base64 header value {value!r}") from exc


def encode_header_value(value: str) -> str:
    """Encode a value for an MCP routing header, using base64 when required."""
    plain = all(0x20 <= ord(ch) <= 0x7E for ch in value) and value == value.strip()
    if plain and not (value.startswith("=?base64?") and value.endswith("?=")):
        return value
    return "=?base64?" + base64.b64encode(value.encode("utf-8")).decode("ascii") + "?="


def expected_name(method: str, params: Any) -> str | None:
    """The value ``Mcp-Name`` must carry for this request, or None if not required."""
    source = NAME_SOURCES.get(method)
    if source is None or not isinstance(params, Mapping):
        return None
    value = params.get(source)
    return value if isinstance(value, str) else None


def param_header_map(input_schema: Any) -> dict[str, tuple[str, ...]]:
    """Map ``Mcp-Param-{Name}`` headers (lower-cased) to argument paths.

    Follows ``x-mcp-header`` annotations through nested ``properties`` only,
    as the spec requires.
    """
    out: dict[str, tuple[str, ...]] = {}

    def walk(schema: Any, path: tuple[str, ...]) -> None:
        if not isinstance(schema, Mapping):
            return
        header = schema.get("x-mcp-header")
        if path and isinstance(header, str) and header:
            out[f"mcp-param-{header.lower()}"] = path
        props = schema.get("properties")
        if isinstance(props, Mapping):
            for key, sub in props.items():
                walk(sub, (*path, str(key)))

    walk(input_schema, ())
    return out


def header_param_value(arguments: Mapping[str, Any], path: tuple[str, ...]) -> str | None:
    """Render the argument at ``path`` as an ``Mcp-Param-*`` value (None to omit)."""
    value: Any = arguments
    for key in path:
        if not isinstance(value, Mapping) or key not in value:
            return None
        value = value[key]
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return encode_header_value(value)
    return None  # floats, objects and arrays are not allowed in headers


# ------------------------------------------------------------------- skills


def skill_path(uri: str) -> str | None:
    """``skill://acme/pdf/SKILL.md`` -> ``acme/pdf``; files keep their full path.

    Returns None for URIs outside the ``skill://`` scheme.
    """
    if not uri.startswith(SKILL_SCHEME):
        return None
    path = uri[len(SKILL_SCHEME) :].strip("/")
    if path.endswith("/SKILL.md"):
        path = path[: -len("/SKILL.md")]
    elif path == "SKILL.md":
        path = ""
    return path


# -------------------------------------------------------------------- tasks


@dataclass
class TaskRecord:
    task_id: str
    agent_id: str
    tool: str
    created: float = field(default_factory=time.time)
    expires: float | None = None


class TaskRegistry:
    """Remembers which agent created which task through this gateway.

    ``tasks/get``, ``tasks/update`` and ``tasks/cancel`` carry only a
    ``taskId``, no tool name. The registry lets the gateway (a) attribute
    task results to the original tool in the audit trail and (b) refuse task
    requests from an agent other than the one whose ``tools/call`` created it.

    It is in-memory and per process. Behind several gateway replicas, either
    route by ``Mcp-Name`` so each task reaches the replica that created it, or
    set ``tasks.bind_to_agent: false``.
    """

    def __init__(self, default_ttl: float = 3600.0) -> None:
        self.default_ttl = default_ttl
        self._tasks: dict[str, TaskRecord] = {}
        self._lock = threading.Lock()

    def add(self, task_id: str, agent_id: str, tool: str, ttl_ms: Any = None) -> TaskRecord:
        ttl = self.default_ttl
        if isinstance(ttl_ms, (int, float)) and ttl_ms > 0:
            ttl = max(ttl, ttl_ms / 1000 * 2)  # outlive the server's own TTL a little
        record = TaskRecord(task_id, agent_id, tool, expires=time.time() + ttl)
        with self._lock:
            self._prune()
            self._tasks[task_id] = record
        return record

    def get(self, task_id: str) -> TaskRecord | None:
        with self._lock:
            record = self._tasks.get(task_id)
            if record and record.expires is not None and record.expires < time.time():
                del self._tasks[task_id]
                return None
            return record

    def discard(self, task_id: str) -> None:
        with self._lock:
            self._tasks.pop(task_id, None)

    def __len__(self) -> int:
        return len(self._tasks)

    def _prune(self) -> None:
        now = time.time()
        for key in [k for k, r in self._tasks.items() if r.expires and r.expires < now]:
            del self._tasks[key]
