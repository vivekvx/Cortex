from __future__ import annotations

import re
from typing import Any, Iterable, List

from cortex_shield.models import RiskAssessment, RiskLevel, ToolCall, ToolKind


class RiskEngine:
    def assess(self, tool_call: ToolCall) -> RiskAssessment:
        reasons: List[str] = []
        score = 10

        if tool_call.tool == ToolKind.SHELL:
            score = max(score, 45)
            reasons.append("shell command")
            command = str(tool_call.payload.get("command", "")).lower()
            score = max(score, self._score_shell(command, reasons))
        elif tool_call.tool == ToolKind.FILESYSTEM:
            score = max(score, 35)
            reasons.append("filesystem access")
            action = tool_call.action.lower()
            if action in {"write", "delete", "chmod", "chown"}:
                score = max(score, 70)
                reasons.append("filesystem mutation")
        elif tool_call.tool == ToolKind.NETWORK:
            score = max(score, 35)
            reasons.append("network access")
        elif tool_call.tool == ToolKind.MEMORY:
            score = max(score, 30)
            reasons.append("memory write")
        else:
            reasons.append("browser action")

        if tool_call.payload.get("_cortex_tainted_source") is True:
            reasons.append("tainted input chain")
            if tool_call.tool in {ToolKind.SHELL, ToolKind.NETWORK}:
                score = max(score, 95)
            elif tool_call.tool == ToolKind.FILESYSTEM and tool_call.action.lower() in {"write", "edit", "delete"}:
                score = max(score, 95)
            else:
                score = max(score, 70)

        if self._contains_prompt_injection(tool_call.payload):
            score = max(score, 95)
            reasons.append("prompt injection pattern")

        return RiskAssessment(level=self._level(score), score=score, reasons=sorted(set(reasons)))

    def _score_shell(self, command: str, reasons: List[str]) -> int:
        score = 45

        if re.search(r"\brm\s+-[^\n]*r[f]?\b|:\(\)\s*\{", command):
            reasons.append("destructive shell pattern")
            score = max(score, 95)

        if re.search(r"~/.ssh|id_rsa|id_ed25519|aws_access_key|secret_access_key|\.env", command):
            reasons.append("credential access pattern")
            score = max(score, 100)

        if re.search(r"curl\b.*\|\s*(sh|bash)|wget\b.*\|\s*(sh|bash)", command):
            reasons.append("remote script execution")
            score = max(score, 85)

        if re.search(r"\bsudo\b|\bchmod\s+777\b|\bchown\b", command):
            reasons.append("privileged shell pattern")
            score = max(score, 75)

        return score

    def _contains_prompt_injection(self, value: Any) -> bool:
        text = " ".join(self._flatten_text(value)).lower()
        patterns = [
            r"ignore (all )?(previous|prior|system) instructions",
            r"upload (ssh keys|keys|credentials|secrets)",
            r"read ~/.ssh",
            r"exfiltrate",
            r"developer mode",
            r"reveal (system prompt|secrets|credentials)",
        ]
        return any(re.search(pattern, text) for pattern in patterns)

    def _flatten_text(self, value: Any) -> Iterable[str]:
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for item in value.values():
                yield from self._flatten_text(item)
        elif isinstance(value, list):
            for item in value:
                yield from self._flatten_text(item)

    def _level(self, score: int) -> RiskLevel:
        if score >= 90:
            return RiskLevel.CRITICAL
        if score >= 70:
            return RiskLevel.HIGH
        if score >= 35:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
