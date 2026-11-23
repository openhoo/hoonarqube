"""Exit codes for the service gate receipt consumed by CI."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

CHECKER = Path(__file__).with_name("check_project_gate.py")
IDENTITY = {"project": "smoke", "branch": "main", "commit": "abc123"}


def receipt(status="pass", *conditions, version=2):
    return {
        "analysis": {
            **IDENTITY,
            "gate_policy_version": version,
            "gate": {
                "schema_version": 3,
                "status": status,
                "conditions": [{"status": state} for state in conditions or (status,)],
            },
        }
    }


class ProjectGateCheckerTest(unittest.TestCase):
    def run_checker(self, data, *args, **identity):
        command = [sys.executable, str(CHECKER)]
        for key, value in (IDENTITY | identity).items():
            command.extend((f"--{key}", value))
        return subprocess.run(
            [*command, *args],
            input=json.dumps(data),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def assert_invalid(self, result, diagnostic):
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn(diagnostic, result.stderr)

    def test_exact_policy_pin_rejects_stale_passing_receipt(self):
        stale = receipt(version=1)
        for pin in ((), ("--policy-version", "1")):
            with self.subTest(pin=pin):
                result = self.run_checker(stale, *pin)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "Project gate version 1: pass")
        self.assert_invalid(
            self.run_checker(stale, "--policy-version", "2"),
            "expected 2, got 1",
        )
        self.assert_invalid(
            self.run_checker(receipt(), "--policy-version", "1"),
            "expected 1, got 2",
        )

    def test_nonpositive_and_nonnumeric_pin_is_invalid(self):
        for version in ("0", "-1", "true", "1.5"):
            with self.subTest(version=version):
                self.assert_invalid(
                    self.run_checker(receipt(), "--policy-version", version),
                    "argument --policy-version",
                )

    def test_receipt_version_and_identity_are_still_required(self):
        for version in (None, True, 0, -1, 2.0, "2"):
            with self.subTest(version=version):
                self.assert_invalid(
                    self.run_checker(receipt(version=version)),
                    "no assigned project gate",
                )
        for field in IDENTITY:
            with self.subTest(field=field):
                self.assert_invalid(
                    self.run_checker(
                        receipt(), "--policy-version", "2", **{field: "other"}
                    ),
                    "different project, branch or commit",
                )

    def test_valid_condition_aggregation_preserves_gate_exit_codes(self):
        cases = (
            ("pass", ("pass",), 0),
            ("pass", ("no_value",), 0),
            ("pass", ("no_value", "pass"), 0),
            ("fail", ("no_value", "fail", "pass"), 1),
            ("unavailable", ("fail", "unavailable"), 2),
            ("unavailable", ("unavailable", "fail"), 2),
        )
        for status, conditions, expected in cases:
            for pin in ((), ("--policy-version", "2")):
                with self.subTest(status=status, conditions=conditions, pin=pin):
                    result = self.run_checker(receipt(status, *conditions), *pin)
                    self.assertEqual(result.returncode, expected, result.stderr)
                    self.assertEqual(result.stderr, "")
                    self.assertEqual(
                        result.stdout.strip(), f"Project gate version 2: {status}"
                    )

    def test_contradictory_aggregate_is_invalid_even_without_pin(self):
        cases = (
            ("pass", ("fail",)),
            ("pass", ("unavailable",)),
            ("fail", ("unavailable", "fail")),
            ("fail", ("pass", "no_value")),
            ("unavailable", ("pass", "fail")),
            ("no_value", ("no_value",)),
        )
        for status, conditions in cases:
            with self.subTest(status=status, conditions=conditions):
                self.assert_invalid(
                    self.run_checker(receipt(status, *conditions)),
                    "Cannot verify assigned gate",
                )

    def test_missing_or_unknown_condition_state_and_wrong_shape_are_invalid(self):
        for conditions in (
            [],
            {"status": "pass"},
            "pass",
            ["pass"],
            [{}],
            [{"status": None}],
            [{"status": {}}],
            [{"status": "unknown"}],
            [{"status": "unavailable"}, {"status": "unknown"}],
        ):
            with self.subTest(conditions=conditions):
                data = receipt("unavailable")
                data["analysis"]["gate"]["conditions"] = conditions
                self.assert_invalid(
                    self.run_checker(data), "Cannot verify assigned gate"
                )

    def test_wrong_schema_is_invalid(self):
        for schema in (2, 3.0, "3"):
            with self.subTest(schema=schema):
                data = receipt()
                data["analysis"]["gate"]["schema_version"] = schema
                self.assert_invalid(
                    self.run_checker(data), "missing or unsupported gate decision"
                )


if __name__ == "__main__":
    unittest.main()
