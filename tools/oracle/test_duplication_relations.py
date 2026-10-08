import copy
import unittest

from duplication_relations import compare


class DuplicationRelationsTests(unittest.TestCase):
    def setUp(self):
        self.native = {
            "project": {
                "complete": True,
                "duplications": [
                    {
                        "occurrences": [
                            {"path": "a.js", "start_line": 1, "end_line": 12},
                            {"path": "b.js", "start_line": 3, "end_line": 14},
                        ]
                    }
                ],
            }
        }
        response = {
            "files": {"1": {"key": "project:a.js"}, "2": {"key": "project:b.js"}},
            "duplications": [
                {
                    "blocks": [
                        {"_ref": "1", "from": 1, "size": 12},
                        {"_ref": "2", "from": 3, "size": 12},
                    ]
                }
            ],
        }
        self.reference = {"a.js": response, "b.js": copy.deepcopy(response)}

    def test_repeated_origin_responses_and_order_do_not_change_relations(self):
        self.reference["b.js"]["duplications"][0]["blocks"].reverse()
        result = compare(self.native, self.reference, "project")
        self.assertTrue(result["matched"])
        self.assertEqual(result["matched_groups"], 1)

    def test_same_counts_with_changed_range_or_resource_fail(self):
        for field, value in [("start_line", 2), ("path", "c.js")]:
            changed = copy.deepcopy(self.native)
            changed["project"]["duplications"][0]["occurrences"][0][field] = value
            self.assertFalse(compare(changed, self.reference, "project")["matched"])

    def test_native_group_and_occurrence_multiplicity_remain_significant(self):
        changed = copy.deepcopy(self.native)
        changed["project"]["duplications"].append(
            copy.deepcopy(changed["project"]["duplications"][0])
        )
        self.assertFalse(compare(changed, self.reference, "project")["matched"])
        changed = copy.deepcopy(self.native)
        changed["project"]["duplications"][0]["occurrences"].append(
            copy.deepcopy(changed["project"]["duplications"][0]["occurrences"][0])
        )
        self.assertFalse(compare(changed, self.reference, "project")["matched"])

    def test_incomplete_native_and_foreign_reference_are_rejected(self):
        self.native["project"]["complete"] = False
        with self.assertRaisesRegex(ValueError, "incomplete"):
            compare(self.native, self.reference, "project")
        self.native["project"]["complete"] = True
        with self.assertRaisesRegex(ValueError, "foreign"):
            compare(self.native, self.reference, "other")

    def test_invalid_range_and_parent_path_are_rejected(self):
        for field, value in [("path", "../outside.js"), ("start_line", 0)]:
            changed = copy.deepcopy(self.native)
            changed["project"]["duplications"][0]["occurrences"][0][field] = value
            with self.assertRaises(ValueError):
                compare(changed, self.reference, "project")


if __name__ == "__main__":
    unittest.main()
