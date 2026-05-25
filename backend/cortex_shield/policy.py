from __future__ import annotations

from cortex_shield.models import DecisionAction, PolicyDecision, RiskAssessment, RiskLevel, ToolCall


class PolicyEngine:
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

        if assessment.level in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
            return PolicyDecision(
                action=DecisionAction.REQUIRE_APPROVAL,
                reason="high risk action requires human approval",
            )

        return PolicyDecision(action=DecisionAction.ALLOW, reason="risk accepted")
