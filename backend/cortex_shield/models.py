from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4


class ToolKind(str, Enum):
    SHELL = "shell"
    BROWSER = "browser"
    FILESYSTEM = "filesystem"
    NETWORK = "network"
    MEMORY = "memory"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DecisionAction(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"


@dataclass(frozen=True)
class ToolCall:
    tool: ToolKind
    action: str
    payload: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "ToolCall":
        return cls(tool=ToolKind(raw["tool"]), action=raw["action"], payload=raw.get("payload", {}))

    def to_dict(self) -> Dict[str, Any]:
        return {"tool": self.tool.value, "action": self.action, "payload": self.payload}


@dataclass(frozen=True)
class RiskAssessment:
    level: RiskLevel
    score: int
    reasons: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {"level": self.level.value, "score": self.score, "reasons": self.reasons}


@dataclass(frozen=True)
class PolicyDecision:
    action: DecisionAction
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {"action": self.action.value, "reason": self.reason}


@dataclass(frozen=True)
class Run:
    name: str
    id: str = field(default_factory=lambda: str(uuid4()))
    created_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "name": self.name, "created_at": self.created_at}


@dataclass(frozen=True)
class TraceEvent:
    run_id: str
    tool_call: ToolCall
    assessment: RiskAssessment
    decision: PolicyDecision
    id: str = field(default_factory=lambda: str(uuid4()))
    created_at: Optional[str] = None
    approval_status: Optional[str] = None
    output: Optional[Any] = None
    error: Optional[str] = None
    taint: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "run_id": self.run_id,
            "tool_call": self.tool_call.to_dict(),
            "assessment": self.assessment.to_dict(),
            "decision": self.decision.to_dict(),
            "approval_status": self.approval_status,
            "output": self.output,
            "error": self.error,
            "taint": self.taint,
            "created_at": self.created_at,
        }


@dataclass(frozen=True)
class ExecutionResult:
    event: TraceEvent
    assessment: RiskAssessment
    decision: PolicyDecision
    output: Optional[Any] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event": self.event.to_dict(),
            "assessment": self.assessment.to_dict(),
            "decision": self.decision.to_dict(),
            "output": self.output,
            "error": self.error,
        }
