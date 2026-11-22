"""Protect domain distinctions that can otherwise turn missing evidence into a pass."""

import gzip
import json
import unittest

from community_profiles import FIXTURE, check_bundle


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

    def test_reused_task_is_not_an_independent_reference(self):
        observations = self.bundle["projects"][0]["observations"]
        observations["core"]["evidence"]["task"] = observations["extended"]["evidence"][
            "task"
        ]
        with self.assertRaisesRegex(ValueError, "reused"):
            check_bundle(self.bundle)
