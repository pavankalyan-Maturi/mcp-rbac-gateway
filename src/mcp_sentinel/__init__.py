"""mcp-sentinel: security, RBAC and audit gateway for MCP servers and AI agents."""

from __future__ import annotations

__version__ = "0.1.1"

from .audit import AuditEvent, AuditLog
from .config import SentinelConfig, load_config
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
from .models import AuditDecision, CallVerdict, Finding, PolicyAction, PolicyDecision, ScanResult
from .policy import PolicyEngine
from .proxy import HttpProxy, MessageInterceptor, StdioProxy, guard
from .scanner import Scanner

__all__ = [
    "ApprovalBroker",
    "ApprovalGate",
    "ApprovalRequest",
    "ApprovalResponse",
    "Approver",
    "AuditDecision",
    "AuditEvent",
    "AuditLog",
    "AutoApprover",
    "CLIApprover",
    "CallVerdict",
    "CallbackApprover",
    "Finding",
    "HttpProxy",
    "MessageInterceptor",
    "PolicyAction",
    "PolicyDecision",
    "PolicyEngine",
    "ResultCheck",
    "ScanResult",
    "Scanner",
    "Sentinel",
    "SentinelConfig",
    "StdioProxy",
    "ToolBlockedError",
    "WebhookApprover",
    "__version__",
    "agent_context",
    "create_approval_router",
    "current_agent",
    "guard",
    "load_config",
]
