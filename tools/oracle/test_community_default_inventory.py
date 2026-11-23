import unittest

from community_default_inventory import HERE, catalog_keys, compare, load_reference


class CommunityDefaultInventory(unittest.TestCase):
    def test_shipped_catalog_retains_observed_active_keys(self):
        reference = load_reference()
        profiles = reference["profiles"]
        rows = compare(profiles, catalog_keys(HERE.parents[1] / "catalog/rules"))
        self.assertEqual(reference["version"], "26.11.0.134175")
        self.assertEqual(
            (len(rows), sum(r["active"] for r in rows.values())), (24, 1702)
        )
        self.assertEqual(
            sum(len(p["catalog_keys_at_capture"]) for p in profiles.values()), 898
        )
        self.assertEqual(rows["ipynb"]["active"], 230)
        self.assertEqual(rows["json"]["active"], 0)

    def test_language_and_rule_identity_matter_but_additions_are_allowed(self):
        profile = {
            "name": "Core",
            "language_name": "Example",
            "active_rule_count": 2,
            "rules": {"example:A": {}, "example:B": {}},
            "catalog_keys_at_capture": ["example:A"],
        }
        with self.assertRaisesRegex(ValueError, "example:A"):
            compare({"ex": profile}, {"other": {"example:A", "example:B"}})
        row = compare({"ex": profile}, {"ex": {"example:A", "example:B"}})["ex"]
        self.assertEqual(row["added_since_capture"], ["example:B"])
        self.assertEqual(row["absent_keys"], [])
