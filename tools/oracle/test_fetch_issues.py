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
    def test_fetches_every_page_and_normalizes_issues(self):
        pages = [
            response(
                {
                    "issues": [
                        {
                            "rule": "python:S100",
                            "line": 3,
                            "message": "rename it",
                            "component": "project:fixtures/example.py",
                        }
                    ],
                    "paging": {"pageIndex": 1, "total": 2, "pageSize": 1},
                }
            ),
            response(
                {
                    "issues": [
                        {
                            "rule": "python:S101",
                            "component": "project:fixtures/other.py",
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
                    "line": 3,
                    "message": "rename it",
                    "file": "example.py",
                },
                {
                    "rule": "python:S101",
                    "line": None,
                    "message": "",
                    "file": "other.py",
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


if __name__ == "__main__":
    unittest.main()
