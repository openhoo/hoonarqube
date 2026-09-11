import base64
import io
import json
import os
import unittest
from pathlib import Path
from unittest import mock


import fetch_issues


def response(payload):
    body = io.BytesIO(json.dumps(payload).encode())
    body.__enter__ = lambda: body
    body.__exit__ = lambda *_args: None
    return body


class FetchIssuesAuthenticationTests(unittest.TestCase):
    def test_environment_token_builds_sonar_basic_header(self):
        with mock.patch.dict(
            os.environ, {"SONAR_ORACLE_TOKEN": "oracle-token"}, clear=True
        ):
            header = fetch_issues.auth_header()

        encoded = base64.b64encode(b"oracle-token:").decode()
        self.assertEqual(header, f"Basic {encoded}")

    def test_missing_token_fails_closed(self):
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(Path, "is_file", return_value=False),
            self.assertRaisesRegex(RuntimeError, "set SONAR_ORACLE_TOKEN"),
        ):
            fetch_issues.auth_header()

    def test_empty_environment_token_fails_closed(self):
        with (
            mock.patch.dict(os.environ, {"SONAR_ORACLE_TOKEN": ""}, clear=True),
            self.assertRaisesRegex(RuntimeError, "must not be empty"),
        ):
            fetch_issues.auth_header()


class FetchIssuesPaginationTests(unittest.TestCase):
    def test_repeated_issue_key_across_pages_fails_closed(self):
        item = {
            "key": "same",
            "rule": "python:S1",
            "message": "finding",
            "component": "oracle-project:src/a.py",
        }
        pages = [
            response(
                {
                    "issues": [item],
                    "paging": {"pageIndex": page, "pageSize": 1, "total": 2},
                }
            )
            for page in (1, 2)
        ]
        with (
            mock.patch.object(fetch_issues, "auth_header", return_value="Basic token"),
            mock.patch.object(
                fetch_issues.urllib.request, "urlopen", side_effect=pages
            ),
            self.assertRaisesRegex(ValueError, "duplicate.*key"),
        ):
            fetch_issues.fetch("oracle-project")

    def test_fetches_every_page_and_normalizes_issues(self):
        pages = [
            response(
                {
                    "issues": [
                        {
                            "key": "first-issue",
                            "rule": "python:S100",
                            "line": 3,
                            "message": "rename it",
                            "component": "project:fixtures/example.py",
                            "textRange": {
                                "startLine": 3,
                                "startOffset": 1,
                                "endLine": 3,
                                "endOffset": 4,
                            },
                        }
                    ],
                    "paging": {"pageIndex": 1, "total": 2, "pageSize": 1},
                }
            ),
            response(
                {
                    "issues": [
                        {
                            "key": "second-issue",
                            "rule": "python:S101",
                            "component": "project:fixtures/other.py",
                            "message": "file issue",
                        }
                    ],
                    "paging": {"pageIndex": 2, "total": 2, "pageSize": 1},
                }
            ),
        ]
        requests = []

        def open_request(request, *, timeout):
            requests.append((request, timeout))
            return pages.pop(0)

        with (
            mock.patch.object(fetch_issues, "auth_header", return_value="Basic token"),
            mock.patch.object(fetch_issues.urllib.request, "urlopen", open_request),
        ):
            issues = fetch_issues.fetch("oracle-project")

        self.assertEqual(
            issues,
            [
                {
                    "rule": "python:S100",
                    "message": "rename it",
                    "file": "example.py",
                    "range": {
                        "start": {"line": 3, "column": 1},
                        "end": {"line": 3, "column": 4},
                    },
                    "hotspot": False,
                },
                {
                    "rule": "python:S101",
                    "message": "file issue",
                    "file": "other.py",
                    "range": None,
                    "hotspot": False,
                },
            ],
        )
        self.assertEqual(len(requests), 2)
        self.assertIn("p=1", requests[0][0].full_url)
        self.assertIn("p=2", requests[1][0].full_url)
        self.assertEqual(requests[0][0].get_header("Authorization"), "Basic token")
        self.assertTrue(
            all(timeout == fetch_issues.HTTP_TIMEOUT_SECONDS for _, timeout in requests)
        )

    def test_truncated_page_fails_closed(self):
        page = response(
            {
                "issues": [],
                "paging": {"pageIndex": 1, "total": 1, "pageSize": 500},
            }
        )
        with (
            mock.patch.object(fetch_issues, "auth_header", return_value="Basic token"),
            mock.patch.object(
                fetch_issues.urllib.request, "urlopen", return_value=page
            ),
            self.assertRaisesRegex(ValueError, "returned 0 items, expected 1"),
        ):
            fetch_issues.fetch("oracle-project")

    def test_zero_page_size_fails_closed(self):
        page = response(
            {
                "issues": [],
                "paging": {"pageIndex": 1, "total": 0, "pageSize": 0},
            }
        )
        with (
            mock.patch.object(fetch_issues, "auth_header", return_value="Basic token"),
            mock.patch.object(
                fetch_issues.urllib.request, "urlopen", return_value=page
            ),
            self.assertRaisesRegex(ValueError, "pageSize must be positive"),
        ):
            fetch_issues.fetch("oracle-project")

    def test_security_fetch_requests_complete_issue_fields_and_preserves_evidence(self):
        page = response(
            {
                "issues": [
                    {
                        "key": "security-1",
                        "rule": "python:S2077",
                        "type": "VULNERABILITY",
                        "message": "unsafe query",
                        "component": "oracle-project:src/a.py",
                        "textRange": {
                            "startLine": 2,
                            "startOffset": 1,
                            "endLine": 2,
                            "endOffset": 4,
                        },
                        "flows": [
                            {
                                "locations": [
                                    {
                                        "component": "oracle-project:src/source.py",
                                        "msg": "source",
                                        "textRange": {
                                            "startLine": 1,
                                            "startOffset": 0,
                                            "endLine": 1,
                                            "endOffset": 3,
                                        },
                                    }
                                ]
                            }
                        ],
                        "secondaryLocations": [
                            {
                                "component": "oracle-project:src/sink.py",
                                "message": "sink",
                                "textRange": {
                                    "startLine": 8,
                                    "startOffset": 0,
                                    "endLine": 8,
                                    "endOffset": 4,
                                },
                            }
                        ],
                        "status": "OPEN",
                        "resolution": None,
                        "assignee": None,
                    }
                ],
                "paging": {"pageIndex": 1, "pageSize": 500, "total": 1},
            }
        )
        requests = []

        def open_request(request, *, timeout):
            requests.append((request, timeout))
            return page

        with (
            mock.patch.object(fetch_issues, "auth_header", return_value="Basic token"),
            mock.patch.object(fetch_issues.urllib.request, "urlopen", open_request),
        ):
            artifact = fetch_issues.fetch_security("oracle-project")

        self.assertIn("additionalFields=_all", requests[0][0].full_url)
        finding = artifact["findings"][0]
        self.assertEqual(finding["file"], "src/a.py")
        self.assertEqual(finding["detector"]["kind"], "VULNERABILITY")
        self.assertEqual(finding["detector"]["flows"][0][0]["file"], "src/source.py")
        self.assertEqual(
            finding["detector"]["secondary_locations"][0]["file"], "src/sink.py"
        )
        self.assertEqual(finding["review"]["status"], "OPEN")
        self.assertEqual(artifact["limits"], [])

    def test_security_fetch_retains_issue_when_flow_location_message_is_unavailable(
        self,
    ):
        page = response(
            {
                "issues": [
                    {
                        "key": "security-flow-without-message",
                        "rule": "python:S2077",
                        "type": "VULNERABILITY",
                        "message": "unsafe query",
                        "component": "oracle-project:src/a.py",
                        "textRange": {
                            "startLine": 2,
                            "startOffset": 1,
                            "endLine": 2,
                            "endOffset": 4,
                        },
                        "flows": [
                            {
                                "locations": [
                                    {
                                        "component": "oracle-project:src/source.py",
                                        "textRange": {
                                            "startLine": 1,
                                            "startOffset": 0,
                                            "endLine": 1,
                                            "endOffset": 3,
                                        },
                                        "msgFormattings": [],
                                    }
                                ]
                            }
                        ],
                        "status": "OPEN",
                        "resolution": None,
                        "assignee": None,
                    }
                ],
                "paging": {"pageIndex": 1, "pageSize": 500, "total": 1},
            }
        )
        with (
            mock.patch.object(fetch_issues, "auth_header", return_value="Basic token"),
            mock.patch.object(
                fetch_issues.urllib.request, "urlopen", return_value=page
            ),
        ):
            artifact = fetch_issues.fetch_security("oracle-project")

        finding = artifact["findings"][0]
        self.assertEqual(finding["detector"]["flows"], [])
        self.assertFalse(finding["detector"]["flow_evidence_available"])
        self.assertIn("python:S2077:flow-evidence-unavailable", artifact["limits"])

    def test_hotspot_fetch_records_unavailable_flow_and_range_evidence(self):
        page = response(
            {
                "hotspots": [
                    {
                        "key": "hotspot-1",
                        "ruleKey": "python:S2245",
                        "message": "randomness",
                        "component": "oracle-project:src/a.py",
                        "line": 4,
                        "status": "TO_REVIEW",
                        "resolution": None,
                        "assignee": None,
                    }
                ],
                "paging": {"pageIndex": 1, "pageSize": 500, "total": 1},
            }
        )
        with (
            mock.patch.object(fetch_issues, "auth_header", return_value="Basic token"),
            mock.patch.object(
                fetch_issues.urllib.request, "urlopen", return_value=page
            ),
        ):
            artifact = fetch_issues.fetch_security("oracle-project", hotspot=True)
        self.assertEqual(
            artifact["findings"][0]["detector"]["kind"], "SECURITY_HOTSPOT"
        )
        self.assertIn("flow-evidence-unavailable", artifact["limits"][0])
        self.assertTrue(
            any(
                "primary-range-evidence-unavailable" in limit
                for limit in artifact["limits"]
            )
        )

    def test_security_fetch_rejects_unverified_enterprise_edition(self):
        with self.assertRaisesRegex(ValueError, "only certifies community"):
            fetch_issues.fetch_security("oracle-project", edition="enterprise")


if __name__ == "__main__":
    unittest.main()
