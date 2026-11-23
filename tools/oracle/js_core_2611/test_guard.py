"""The CI comparison must reject swapped observations even when counts stay equal."""

from copy import deepcopy
import unittest

from replay import HERE, guard, read


class PublicGuardTest(unittest.TestCase):
    def setUp(self):
        self.prior = read(HERE / "observed.json")
        self.candidate = deepcopy(self.prior)

    def test_fixing_previous_extra_and_missing_issues_is_allowed(self):
        for row in self.candidate["controls"]:
            row["missing"] = []
            row["additional"] = []
        guard(self.candidate, self.prior)

    def test_same_count_with_a_different_primary_span_is_not_an_improvement(self):
        for kind in ("additional", "missing"):
            with self.subTest(kind=kind):
                candidate = deepcopy(self.prior)
                row = next(x for x in candidate["controls"] if x[kind])
                row[kind][0][3] += 1
                with self.assertRaisesRegex(ValueError, "primary locations"):
                    guard(candidate, self.prior)

    def test_matching_locations_with_a_new_export_metadata_difference_fail(self):
        self.candidate["controls"][1]["metadata_differences"] = {
            "javascript:S7767": {"severity": {"export": "INFO", "reference": "MAJOR"}}
        }
        with self.assertRaisesRegex(ValueError, "metadata"):
            guard(self.candidate, self.prior)

    def test_a_different_revision_cannot_inherit_the_old_exceptions(self):
        self.candidate["controls"][1]["revision"] = "1" * 40
        with self.assertRaisesRegex(ValueError, "reference changed"):
            guard(self.candidate, self.prior)
