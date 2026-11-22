"""Location and multiplicity matter even if the project-wide counts are unchanged."""

import unittest
from collections import Counter

from public_locations import difference


class PublicLocationTest(unittest.TestCase):
    def test_moved_primary_with_same_totals_is_not_an_improvement(self):
        expected = ("ruby:S1192", "a.rb", 1, 2, 1, 5)
        old = ("ruby:S1192", "a.rb", 2, 2, 2, 5)
        other = ("ruby:S1192", "a.rb", 3, 2, 3, 5)
        ref = Counter([expected])
        with self.assertRaisesRegex(ValueError, "new differences"):
            difference(Counter([other]), ref, ref, Counter([old]))
        self.assertEqual(
            difference(ref, ref, ref, Counter([old])),
            {"matched": 1, "native_only": 0, "reference_only": 0},
        )

    def test_removing_an_exact_duplicate_fails(self):
        key = ("go:S100", "a.go", 1, 0, 1, 3)
        with self.assertRaisesRegex(ValueError, "new differences"):
            difference(Counter([key]), Counter([key, key]), Counter(), Counter())
        with self.assertRaisesRegex(ValueError, "new differences"):
            difference(
                Counter([key, key, key]), Counter([key]), Counter(), Counter([key])
            )
