"""Protect domain distinctions that can otherwise turn missing evidence into a pass."""

import gzip
import json
import unittest
from collections import Counter

from community_profiles import FIXTURE, check_bundle, tightened
from public_locations import difference


class CommunityProfilesTests(unittest.TestCase):
    def setUp(self):
        self.bundle = json.loads(gzip.decompress(FIXTURE.read_bytes()))

    def test_other_tier_cannot_be_substituted(self):
        observations = self.bundle["projects"][0]["observations"]
        observations["extended"], observations["core"] = (
            observations["core"],
            observations["extended"],
        )
        with self.assertRaisesRegex(ValueError, "different profile"):
            check_bundle(self.bundle)

    def test_unavailable_language_cannot_count_as_measured(self):
        self.bundle["without_reference_language"].pop()
        with self.assertRaisesRegex(ValueError, "unavailable scope"):
            check_bundle(self.bundle)

    def test_ruby_rule_cannot_enter_a_comparable_profile(self):
        observation = self.bundle["projects"][0]["observations"]["core"]
        observation["parameters"]["ruby:S1192"] = {}
        with self.assertRaisesRegex(ValueError, "outside the indexed language"):
            check_bundle(self.bundle)

    def test_resolution_removes_only_the_named_captured_location(self):
        first = ("python:S3827", "example.py", 2, 4, 2, 5)
        second = ("python:S3827", "example.py", 3, 4, 3, 5)
        case = {"repository": "owner/project", "missing": [first, second], "extra": []}
        resolved = {("owner/project", "core", "missing"): Counter([first])}
        result = tightened(case.copy(), "core", resolved)
        self.assertEqual(result["missing"], [second])
        self.assertEqual(tightened(case.copy(), "extended", resolved), case)
        reference = Counter([first, second])
        with self.assertRaisesRegex(ValueError, "new differences: missing"):
            difference(Counter(), reference, Counter(result["missing"]), Counter())
        self.assertEqual(
            difference(
                Counter([first]), reference, Counter(result["missing"]), Counter()
            ),
            {"matched": 1, "native_only": 0, "reference_only": 1},
        )
        with self.assertRaisesRegex(ValueError, "outside archived allowance"):
            tightened(result, "core", resolved)

    def test_resolution_cannot_target_an_unmeasured_ruby_project(self):
        source = next(
            item
            for item in self.bundle["without_reference_language"]
            if item["language"] == "ruby"
        )
        resolved = {
            (source["repository"], "core", "missing"): Counter(
                [("ruby:S1192", "lib/example.rb", 2, 4, 2, 5)]
            )
        }
        with self.assertRaisesRegex(ValueError, "unmeasured project or profile"):
            check_bundle(self.bundle, resolved)

    def test_reused_task_is_not_an_independent_reference(self):
        observations = self.bundle["projects"][0]["observations"]
        observations["core"]["evidence"]["task"] = observations["extended"]["evidence"][
            "task"
        ]
        with self.assertRaisesRegex(ValueError, "reused"):
            check_bundle(self.bundle)
