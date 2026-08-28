import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))

from import_smoke import MESSAGE, RULE, verify_imported_issue


def issue(**overrides):
    value = {
        "rule": RULE,
        "message": MESSAGE,
        "textRange": {
            "startLine": 2,
            "endLine": 2,
            "startOffset": 10,
            "endOffset": 39,
        },
    }
    value.update(overrides)
    return value


class ImportSmokeTests(unittest.TestCase):
    def test_accepts_one_exact_external_issue(self):
        expected = issue()
        self.assertEqual(verify_imported_issue({"issues": [expected]}), expected)

    def test_requires_issues_list(self):
        with self.assertRaisesRegex(ValueError, "lacks issues list"):
            verify_imported_issue({})

    def test_requires_exactly_one_matching_issue(self):
        with self.assertRaisesRegex(ValueError, "got 0"):
            verify_imported_issue({"issues": []})
        with self.assertRaisesRegex(ValueError, "got 2"):
            verify_imported_issue({"issues": [issue(), issue()]})

    def test_rejects_message_drift(self):
        with self.assertRaisesRegex(ValueError, "message differs"):
            verify_imported_issue({"issues": [issue(message="Different")]})

    def test_rejects_location_drift(self):
        with self.assertRaisesRegex(ValueError, "range differs"):
            verify_imported_issue(
                {
                    "issues": [
                        issue(
                            textRange={
                                "startLine": 2,
                                "endLine": 2,
                                "startOffset": 9,
                                "endOffset": 39,
                            }
                        )
                    ]
                }
            )


if __name__ == "__main__":
    unittest.main()
