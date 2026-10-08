import copy
import unittest
from secondary_locations import compare


class SupportingLocationComparisonTests(unittest.TestCase):
    def fixture(self):
        span = {"start": {"line": 1, "column": 0}, "end": {"line": 1, "column": 2}}
        sonar_span = {"startLine": 1, "startOffset": 0, "endLine": 1, "endOffset": 2}
        native_location = {"range": span, "message": "+1"}
        reference_location = {
            "component": "p:a.go",
            "textRange": sonar_span,
            "msg": "+1",
        }
        native = {
            "schema_version": 1,
            "project": {"complete": True},
            "files": [
                {
                    "path": "a.go",
                    "issues": [
                        {
                            "rule_key": "go:S3776",
                            "message": "complex",
                            "range": span,
                            "flows": [{"locations": [native_location]}],
                        }
                    ],
                }
            ],
        }
        reference = [
            {
                "rule": "go:S3776",
                "message": "complex",
                "component": "p:a.go",
                "textRange": sonar_span,
                "flows": [{"locations": [reference_location]}],
            }
        ]
        return native, reference

    def test_missing_flow_and_message_mismatch_are_observed(self):
        native, reference = self.fixture()
        self.assertTrue(compare(native, reference, "p", {"go:S3776"})["matched"])
        native["files"][0]["issues"][0]["flows"] = []
        result = compare(native, reference, "p", {"go:S3776"})
        self.assertFalse(result["matched"])
        self.assertEqual(result["native_supporting_locations"], 0)
        self.assertEqual(result["reference_supporting_locations"], 1)
        native, reference = self.fixture()
        native["files"][0]["issues"][0]["message"] = "different"
        self.assertFalse(compare(native, reference, "p", {"go:S3776"})["matched"])

    def test_duplicate_flows_and_ordered_paths_are_not_collapsed(self):
        native, reference = self.fixture()
        issue = native["files"][0]["issues"][0]
        issue["flows"] *= 2
        self.assertFalse(compare(native, reference, "p", {"go:S3776"})["matched"])
        reference[0]["flows"] *= 2
        self.assertTrue(compare(native, reference, "p", {"go:S3776"})["matched"])
        native, reference = self.fixture()
        loc = copy.deepcopy(native["files"][0]["issues"][0]["flows"][0]["locations"][0])
        loc["message"] = "+2"
        native["files"][0]["issues"][0]["flows"][0]["locations"].append(loc)
        loc = copy.deepcopy(reference[0]["flows"][0]["locations"][0])
        loc["msg"] = "+2"
        reference[0]["flows"][0]["locations"].insert(0, loc)
        self.assertFalse(compare(native, reference, "p", {"go:S3776"})["matched"])

    def test_rejects_incomplete_or_foreign_project_evidence(self):
        native, reference = self.fixture()
        native["project"]["complete"] = False
        with self.assertRaises(ValueError):
            compare(native, reference, "p", {"go:S3776"})

    def test_omitted_reference_secondary_message_matches_empty_native_message(self):
        native, reference = self.fixture()
        native["files"][0]["issues"][0]["flows"][0]["locations"][0]["message"] = ""
        del reference[0]["flows"][0]["locations"][0]["msg"]
        self.assertTrue(compare(native, reference, "p", {"go:S3776"})["matched"])
        native["files"][0]["issues"][0]["flows"][0]["locations"][0]["message"] = "+1"
        self.assertFalse(compare(native, reference, "p", {"go:S3776"})["matched"])
        native, reference = self.fixture()
        reference[0]["flows"][0]["locations"][0]["component"] = "other:a.go"
        with self.assertRaises(ValueError):
            compare(native, reference, "p", {"go:S3776"})


if __name__ == "__main__":
    unittest.main()
