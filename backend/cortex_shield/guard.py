from __future__ import annotations

from typing import Any, Callable

from cortex_shield.models import DecisionAction, ExecutionResult, ToolCall
from cortex_shield.policy import PolicyEngine
from cortex_shield.risk import RiskEngine
from cortex_shield.trace_store import TraceStore


class CortexGuard:
    def __init__(
        self,
        store: TraceStore,
        risk_engine: RiskEngine | None = None,
        policy_engine: PolicyEngine | None = None,
    ) -> None:
        self.store = store
        self.risk_engine = risk_engine or RiskEngine()
        self.policy_engine = policy_engine or PolicyEngine()

    def check(self, run_id: str, tool_call: ToolCall) -> ExecutionResult:
        tool_call = self._attach_taint_context(tool_call)
        assessment = self.risk_engine.assess(tool_call)
        decision = self.policy_engine.decide(tool_call, assessment)
        event = self.store.record_event(run_id, tool_call, assessment, decision)
        return ExecutionResult(event=event, assessment=assessment, decision=decision)

    def execute(
        self,
        run_id: str,
        tool_call: ToolCall,
        executor: Callable[[ToolCall], Any],
    ) -> ExecutionResult:
        tool_call = self._attach_taint_context(tool_call)
        assessment = self.risk_engine.assess(tool_call)
        decision = self.policy_engine.decide(tool_call, assessment)

        if decision.action != DecisionAction.ALLOW:
            event = self.store.record_event(run_id, tool_call, assessment, decision)
            return ExecutionResult(event=event, assessment=assessment, decision=decision)

        try:
            output = executor(tool_call)
            event = self.store.record_event(run_id, tool_call, assessment, decision)
            event = self.store.record_result(event.id, output=output) or event
            return ExecutionResult(event=event, assessment=assessment, decision=decision, output=output)
        except Exception as exc:
            event = self.store.record_event(run_id, tool_call, assessment, decision, error=str(exc))
            return ExecutionResult(event=event, assessment=assessment, decision=decision, error=str(exc))

    def _attach_taint_context(self, tool_call: ToolCall) -> ToolCall:
        source_event_id = tool_call.payload.get("source_event_id")
        if not isinstance(source_event_id, str) or not self.store.is_tainted_event(source_event_id):
            return tool_call
        return ToolCall(
            tool=tool_call.tool,
            action=tool_call.action,
            payload={**tool_call.payload, "_cortex_tainted_source": True},
        )
