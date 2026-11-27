"""mcp-rbac-gateway: security, RBAC and audit gateway for MCP servers and AI agents."""

from __future__ import annotations

__version__ = "0.2.0"

from .audit import AuditEvent, AuditLog, AuditPage, create_audit_router
from .config import SentinelConfig, load_config
from .context import CallContext, call_context, current_call_context
from .gateway import ResultCheck, Sentinel, ToolBlockedError, agent_context, current_agent
from .hitl import (
    ApprovalBroker,
    ApprovalGate,
    ApprovalRequest,
    ApprovalResponse,
    Approver,
    AutoApprover,
    CallbackApprover,
    CLIApprover,
    WebhookApprover,
    create_approval_router,
)
from .mcp import RequestMeta, TaskRegistry
from .models import AuditDecision, CallVerdict, Finding, PolicyAction, PolicyDecision, ScanResult
from .policy import PolicyEngine
from .proxy import HttpProxy, MessageInterceptor, StatelessHttpProxy, StdioProxy, guard
from .scanner import Scanner
from .sync import run_sync

__all__ = [
    "ApprovalBroker",
    "ApprovalGate",
    "ApprovalRequest",
    "ApprovalResponse",
    "Approver",
    "AuditDecision",
    "AuditEvent",
    "AuditLog",
    "AuditPage",
    "AutoApprover",
    "CallContext",
    "CLIApprover",
    "CallVerdict",
    "CallbackApprover",
    "Finding",
    "HttpProxy",
    "MessageInterceptor",
    "PolicyAction",
    "PolicyDecision",
    "PolicyEngine",
    "RequestMeta",
    "ResultCheck",
    "ScanResult",
    "Scanner",
    "Sentinel",
    "SentinelConfig",
    "StatelessHttpProxy",
    "StdioProxy",
    "TaskRegistry",
    "ToolBlockedError",
    "WebhookApprover",
    "__version__",
    "agent_context",
    "call_context",
    "create_approval_router",
    "create_audit_router",
    "current_agent",
    "current_call_context",
    "guard",
    "load_config",
    "run_sync",
]
