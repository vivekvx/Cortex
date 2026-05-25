import json
import os
import tempfile
import unittest

from cortex_shield.models import DecisionAction
from cortex_shield.policy_config import load_policy_config


class PolicyConfigTests(unittest.TestCase):
    def test_loads_reason_actions_from_json_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = os.path.join(tmpdir, "policy.json")
            with open(policy_path, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "reason_actions": {
                            "remote script execution": "block",
                            "filesystem mutation": "require_approval",
                        }
                    },
                    handle,
                )

            config = load_policy_config(policy_path)

            self.assertEqual(config.reason_actions["remote script execution"], DecisionAction.BLOCK)
            self.assertEqual(
                config.reason_actions["filesystem mutation"],
                DecisionAction.REQUIRE_APPROVAL,
            )


if __name__ == "__main__":
    unittest.main()
