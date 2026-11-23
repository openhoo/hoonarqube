"""The absence of new reference issues constrains only rules in the assigned profile."""

import unittest

from fastapi_default_gate import check_findings


class DefaultGateTest(unittest.TestCase):
    def test_inactive_and_existing_findings_do_not_mask_new_active_findings(self):
        report = {
            "files": [
                {
                    "path": "a.py",
                    "issues": [
                        {"rule_key": "python:S104"},
                        {"rule_key": "python:S3827"},
                    ],
                }
            ],
            "assessment": {
                "new_code": {
                    "findings": [
                        {"path": "a.py", "issue_index": 0, "status": "new"},
                        {"path": "a.py", "issue_index": 1, "status": "existing"},
                    ]
                }
            },
        }
        self.assertEqual(
            check_findings(report, {"python:S3827": {}}), {"python:S104": 1}
        )
        report["assessment"]["new_code"]["findings"][1]["status"] = "new"
        with self.assertRaisesRegex(ValueError, "active Python core"):
            check_findings(report, {"python:S3827": {}})
