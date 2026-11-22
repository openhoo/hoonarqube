"""A matching percentage must not hide an unrelated analysis or gate decision."""

import copy
import json
import unittest

from commander_reference import REFERENCE, verify
from community_combined_coverage import BASES, REV
from public_coverage_gate_replay import RECEIPT


class CommanderReferenceTests(unittest.TestCase):
    def setUp(self):
        self.case = json.loads(REFERENCE.read_bytes())["cases"]["policy-987f2896"]
        self.digest = json.loads(RECEIPT.read_bytes())["cases"]["focused"][
            "lcov_sha256"
        ]
        self.native = {
            "status": "pass",
            "conditions": [
                {
                    "scope": "new_code",
                    "metric": "coverage",
                    "operator": "gte",
                    "threshold": 95,
                    "actual": 80.0,
                    "status": "pass",
                    "ignored_on_small_change": 5,
                }
            ],
        }

    def compare(self, case):
        return verify(
            case,
            "focused",
            BASES[0],
            REV,
            self.digest,
            (2485, 4201, 148, 232),
            (4, 5, 0, 0),
            5,
            self.native,
            0,
            True,
        )

    def test_wrong_reference_period(self):
        self.compare(self.case)
        for owner, key in (("period", "value"), ("decision", "parameter")):
            with self.subTest(owner=owner):
                changed = copy.deepcopy(self.case)
                ref = changed[owner] if owner == "period" else changed[owner]["period"]
                ref[key] = changed["candidate"]["analysisId"]
                with self.assertRaisesRegex(ValueError, "reference baseline"):
                    self.compare(changed)

    def test_exception_flag_and_counters(self):
        self.case["decision"]["ignoredConditions"] = False
        with self.assertRaisesRegex(ValueError, "ignoredConditions"):
            self.compare(self.case)
        self.case["decision"]["ignoredConditions"] = True
        self.case["measures"]["new_uncovered_lines"] = "0"
        with self.assertRaisesRegex(ValueError, "count differs"):
            self.compare(self.case)
