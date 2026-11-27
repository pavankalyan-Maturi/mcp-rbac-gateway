"""Shared result types."""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field

__all__ = [
    "AuditDecision",
    "CallVerdict",
    "Finding",
    "PolicyAction",
    "PolicyDecision",
    "ScanResult",
]


class PolicyAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class AuditDecision(str, Enum):
    """The final outcome of a tool call, as written to the audit trail."""

    ALLOWED = "allowed"
    BLOCKED_POLICY = "blocked_policy"
    BLOCKED_INJECTION = "blocked_injection"
    APPROVED = "approved"
    DENIED_BY_HUMAN = "denied_by_human"
    APPROVAL_TIMEOUT = "approval_timeout"
    ERROR = "error"
    PENDING_APPROVAL = "pending_approval"
    """Approval was requested. Audit rows with this decision record the request;
    a verdict with it comes from ``check_call(..., wait=False)``."""

    @property
    def is_block(self) -> bool:
        return self in {
            AuditDecision.BLOCKED_POLICY,
            AuditDecision.BLOCKED_INJECTION,
            AuditDecision.DENIED_BY_HUMAN,
            AuditDecision.APPROVAL_TIMEOUT,
        }


class PolicyDecision(BaseModel):
    action: PolicyAction
    reason: str
    rule: str | None = Field(default=None, description="The rule that produced the decision.")

    @property
    def allowed(self) -> bool:
        return self.action is not PolicyAction.DENY


class Finding(BaseModel):
    """A single scanner hit. Never contains the matched secret itself."""

    kind: Literal["secret", "pii", "custom", "injection"] = "secret"
    detector: str
    path: str = Field(description="JSON path of the field where the hit was found.")
    score: float = 1.0
    excerpt: str | None = Field(default=None, description="Safe context for injection hits.")


class ScanResult(BaseModel):
    payload: Any
    findings: list[Finding] = Field(default_factory=list)
    injection_score: float = 0.0

    @property
    def redacted(self) -> bool:
        return any(f.kind in ("secret", "pii", "custom") for f in self.findings)

    @property
    def injection_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.kind == "injection"]


class CallVerdict(BaseModel):
    """Everything sentinel decided about one tool call *before* it runs."""

    agent_id: str
    tool: str = Field(description="Tool name, or the target of another method (skill, task).")
    decision: AuditDecision
    reason: str
    arguments: dict[str, Any] = Field(description="Arguments to forward (possibly redacted).")
    method: str = "tools/call"
    findings: list[Finding] = Field(default_factory=list)
    approver: str | None = None
    approval_id: str | None = Field(
        default=None, description="Id of the approval request, when one was made."
    )

    @property
    def allowed(self) -> bool:
        """True only when the call may run now (allowed, or approved by a human)."""
        return self.decision in (AuditDecision.ALLOWED, AuditDecision.APPROVED)

    @property
    def pending(self) -> bool:
        return self.decision is AuditDecision.PENDING_APPROVAL
