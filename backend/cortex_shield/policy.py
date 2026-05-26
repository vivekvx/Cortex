from __future__ import annotations

from cortex_shield.models import DecisionAction, PolicyDecision, RiskAssessment, RiskLevel, ToolCall
from cortex_shield.policy_config import PolicyConfig


class PolicyEngine:
    def __init__(self, config: PolicyConfig | None = None) -> None:
        self.config = config or PolicyConfig()

    def decide(self, tool_call: ToolCall, assessment: RiskAssessment) -> PolicyDecision:
        reasons = set(assessment.reasons)

        if "credential access pattern" in reasons:
            return PolicyDecision(
                action=DecisionAction.BLOCK,
                reason="credential access is blocked",
            )

        if "prompt injection pattern" in reasons:
            return PolicyDecision(
                action=DecisionAction.BLOCK,
                reason="prompt injection chain is blocked",
            )

        if "tainted input chain" in reasons and assessment.level == RiskLevel.CRITICAL:
            return PolicyDecision(
                action=DecisionAction.BLOCK,
                reason="tainted input chain is blocked",
            )

        for reason in assessment.reasons:
            configured_action = self.config.reason_actions.get(reason)
            if configured_action is not None:
                return PolicyDecision(
                    action=configured_action,
                    reason=f"policy override: {reason}",
                )

        if assessment.level in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
            return PolicyDecision(
                action=DecisionAction.REQUIRE_APPROVAL,
                reason="high risk action requires human approval",
            )

        return PolicyDecision(action=DecisionAction.ALLOW, reason="risk accepted")
