"""Separate current/historical decisions and reject review evidence from another hotspot."""

import copy
import unittest
from pathlib import Path
from community_custom_hotspot import ARCHIVE, load, verify


class CustomHotspotEvidenceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = load(Path(__file__).with_name("fixtures") / ARCHIVE)

    def test_nonempty_review_and_reopen(self):
        self.assertEqual([r["percent"] for r in verify(self.data)], [0, 100, 0])

    def test_live_pass_cannot_replace_immutable_gate(self):
        data = copy.deepcopy(self.data)
        data["after-review-643-analysis-gate"] = data["after-review-643-live-gate"]
        with self.assertRaisesRegex(ValueError, "historical gate"):
            verify(data)

    def test_unrelated_review_cannot_supply_new_code_measure(self):
        data = copy.deepcopy(self.data)
        data["after-review-643-new"]["hotspots"][0]["key"] = "unrelated-review"
        with self.assertRaisesRegex(ValueError, "inventory mismatch"):
            verify(data)

    def test_single_metric_cannot_substitute_for_both_gate_conditions(self):
        data = copy.deepcopy(self.data)
        data["after-review-643-live-gate"]["projectStatus"]["conditions"].pop()
        with self.assertRaisesRegex(ValueError, "gate"):
            verify(data)

    def test_other_projects_percentages_cannot_substitute_for_review(self):
        data = copy.deepcopy(self.data)
        data["after-review-643-measures"]["component"]["key"] = "different-project"
        with self.assertRaisesRegex(ValueError, "wrong project"):
            verify(data)
