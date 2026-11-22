"""Negative controls for reference binding, small changes and ambiguous native results."""

import copy
import unittest

from community_duplication_reference import METRIC, RECEIPT, check_status, read
from community_new_duplication import CONFIG, native_result, validate_cases


class DuplicationComparisonTests(unittest.TestCase):
    def setUp(self):
        self.data = read(RECEIPT)

    def test_excludes_unconfirmed_or_repeated_project(self):
        for replacement in (
            self.data["cases"][-1],
            {
                **self.data["cases"][0],
                "project": "hq-yjs-duplication-20261122-f4078a-76b7d0b6-0a5753c1",
            },
        ):
            with self.subTest(project=replacement["project"]):
                data = copy.deepcopy(self.data)
                data["cases"][0] = replacement
                with self.assertRaisesRegex(ValueError, "five distinct"):
                    validate_cases(data)

    def test_rejects_disconnected_period_or_shared_compute_task(self):
        case = self.data["cases"][0]
        original = case["period"]
        case["period"] = case["candidate"]["analysisId"]
        with self.assertRaisesRegex(ValueError, "period"):
            validate_cases(self.data)
        case["period"] = original
        case["candidate"]["computeId"] = case["base"]["computeId"]
        with self.assertRaisesRegex(ValueError, "reused"):
            validate_cases(self.data)

    def test_short_green_requires_actual_exceedance_before_ignore(self):
        def evaluate(new, dup, ignored, status):
            density = round(100 * dup / new, 4)
            condition = {
                "metricKey": METRIC,
                "comparator": "GT",
                "errorThreshold": "3",
                "actualValue": str(density),
                "status": status,
            }
            response = {
                "period": {"mode": "SPECIFIC_ANALYSIS", "parameter": "base"},
                "conditions": [condition],
                "ignoredConditions": ignored,
                "status": status,
            }
            return check_status(
                response,
                {"new_lines": new, "new_duplicated_lines": dup, METRIC: density},
                "base",
            )

        self.assertTrue(evaluate(19, 1, True, "OK")["ignored"])
        self.assertEqual(evaluate(20, 1, False, "ERROR")["status"], "ERROR")
        for args in ((19, 0, True, "OK"), (20, 1, True, "OK"), (10, 2, False, "OK")):
            with (
                self.subTest(args=args),
                self.assertRaisesRegex(ValueError, "small-change"),
            ):
                evaluate(*args)

    def test_ambiguous_changes_cannot_become_green(self):
        case = self.data["cases"][0]
        report = {
            "assessment": {
                "new_code": {
                    "status": "incomplete",
                    "reference_context": {"source_revision": case["base"]["revision"]},
                    "diagnostics": ["ambiguous baseline line mapping"],
                },
                "gate": {
                    "status": "pass",
                    "conditions": [{**CONFIG, "status": "pass", "actual": 0.0}],
                },
            }
        }
        with self.assertRaisesRegex(ValueError, "ambiguous source must be unavailable"):
            native_result(report, 0, case, set(range(1, 87)))

    def test_reference_density_cannot_be_replaced_by_native_value(self):
        case = self.data["cases"][2]
        case["reference"]["density"] = case["native"]["density"]
        with self.assertRaisesRegex(ValueError, "reference counters"):
            validate_cases(self.data)


if __name__ == "__main__":
    unittest.main()
