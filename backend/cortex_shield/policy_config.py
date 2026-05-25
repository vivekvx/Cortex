from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, Optional

from cortex_shield.models import DecisionAction


@dataclass(frozen=True)
class PolicyConfig:
    reason_actions: Dict[str, DecisionAction] = field(default_factory=dict)


def load_policy_config(path: Optional[str]) -> PolicyConfig:
    if not path:
        return PolicyConfig()

    with open(path, "r", encoding="utf-8") as handle:
        raw = json.load(handle)

    reason_actions_raw = raw.get("reason_actions", {})
    if not isinstance(reason_actions_raw, dict):
        raise ValueError("reason_actions must be an object")

    reason_actions: Dict[str, DecisionAction] = {}
    for reason, action in reason_actions_raw.items():
        if not isinstance(reason, str) or not isinstance(action, str):
            raise ValueError("reason_actions keys and values must be strings")
        reason_actions[reason] = DecisionAction(action)

    return PolicyConfig(reason_actions=reason_actions)
