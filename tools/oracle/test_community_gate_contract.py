"""Negative controls for the translation from a Community response to a native gate."""

import copy
import json
import unittest

from community_gate_contract import (
    DUPLICATION,
    RECEIPT,
    coverage_reference,
    duplication_reference,
)


class CommunityGateContractTests(unittest.TestCase):
    def setUp(self):
        self.coverage = json.loads(RECEIPT.read_bytes())["cases"]
        self.yjs = json.loads(DUPLICATION.read_bytes())["cases"]["yjs"]

    def coverage_report(self, case_name, mode):
        case = self.coverage[case_name]
        native = case[
            "native_full_precision" if mode == "full" else "native_one_decimal"
        ]
        lines = case["native_full_precision"]["lines"]
        return {
            "assessment": {
                "gate": {
                    "status": native["gate"],
                    "conditions": [copy.deepcopy(native["condition"])],
                },
                "coverage": {"lines": lines} if lines else None,
            }
        }

    def test_changed_reference_verdict_fails_even_if_native_report_still_matches_its_capture(
        self,
    ):
        case = self.coverage["focused"]
        report = self.coverage_report("focused", "full")
        case["reference"]["gate"] = case["reference"]["condition"]["status"] = "OK"
        with self.assertRaisesRegex(ValueError, "Community coverage verdict"):
            coverage_reference("focused", "full", case, report)

    def test_missing_input_cannot_be_substituted_with_measured_zero(self):
        report = self.coverage_report("missing", "full")
        assessment = report["assessment"]
        assessment["coverage"] = {"lines": {"eligible": 1252, "covered": 0}}
        condition = assessment["gate"]["conditions"][0]
        condition["actual"] = 0.0
        assessment["gate"]["status"] = condition["status"] = "fail"
        with self.assertRaisesRegex(ValueError, "missing LCOV"):
            coverage_reference("missing", "full", self.coverage["missing"], report)

    def test_rounded_boundary_needs_an_explicit_precision(self):
        report = self.coverage_report("decimal", "one_decimal")
        del report["assessment"]["gate"]["conditions"][0]["precision"]
        with self.assertRaisesRegex(ValueError, "precision"):
            coverage_reference(
                "decimal", "one_decimal", self.coverage["decimal"], report
            )

    def test_full_precision_must_still_fail_below_the_rounded_threshold(self):
        report = self.coverage_report("decimal", "full")
        gate = report["assessment"]["gate"]
        gate["status"] = gate["conditions"][0]["status"] = "pass"
        with self.assertRaisesRegex(ValueError, "coverage verdict differs"):
            coverage_reference("decimal", "full", self.coverage["decimal"], report)

    def test_duplication_cannot_match_by_verdict_alone(self):
        reference, gate = (
            self.yjs["reference"],
            self.yjs["native"]["assessment"]["gate"],
        )
        next(
            c
            for c in reference["projectStatus"]["conditions"]
            if c["metricKey"] == "duplicated_lines"
        )["actualValue"] = "140"
        with self.assertRaisesRegex(
            ValueError, "duplicated_lines: duplication measurement differs"
        ):
            duplication_reference(reference, gate)

    def test_missing_or_ignored_duplication_conditions_fail(self):
        reference, gate = (
            self.yjs["reference"],
            self.yjs["native"]["assessment"]["gate"],
        )
        for change, error in (
            ("ignored", "ignored"),
            ("missing", "missing"),
            ("empty", "missing"),
        ):
            with self.subTest(change=change):
                updated = copy.deepcopy(reference)
                if change == "ignored":
                    updated["projectStatus"]["ignoredConditions"] = True
                elif change == "missing":
                    updated["projectStatus"]["conditions"].pop()
                else:
                    updated["projectStatus"]["conditions"] = []
                with self.assertRaisesRegex(ValueError, error):
                    duplication_reference(updated, gate)


if __name__ == "__main__":
    unittest.main()
