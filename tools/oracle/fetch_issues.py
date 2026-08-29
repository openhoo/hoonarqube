#!/usr/bin/env python3
"""Fetch all issues for one SonarQube project via pagination."""

import argparse
import base64
import json
import os
import urllib.parse
import urllib.request
from pathlib import Path

from parity import validate_search_page


REPO = Path(__file__).resolve().parent.parent.parent
BASE = os.environ.get("SONAR_ORACLE_URL", "http://127.0.0.1:9000").rstrip("/")
HTTP_TIMEOUT_SECONDS = 30


def auth_header():
    """Build SonarQube basic authentication from the configured token."""
    token = os.environ.get("SONAR_ORACLE_TOKEN")
    if token is None:
        token_path = REPO / ".oracle/sonar/token"
        if not token_path.is_file():
            raise RuntimeError("set SONAR_ORACLE_TOKEN or create .oracle/sonar/token")
        token = token_path.read_text().strip()
    if not token:
        raise RuntimeError("SONAR_ORACLE_TOKEN must not be empty")
    encoded = base64.b64encode(f"{token}:".encode()).decode()
    return f"Basic {encoded}"


def fetch(component):
    """Return every normalized issue for `component` or reject weak paging."""
    issues, page = [], 1
    authorization = auth_header()
    expected_total = expected_page_size = None
    while True:
        q = urllib.parse.urlencode(
            {
                "componentKeys": component,
                "resolved": "false",
                "ps": 500,
                "p": page,
                "s": "FILE_LINE",
                "asc": "true",
            }
        )
        req = urllib.request.Request(f"{BASE}/api/issues/search?{q}")
        req.add_header("Authorization", authorization)
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as response:
            d = json.load(response)
        page_issues, total, page_size, done = validate_search_page(
            d,
            "issues",
            page,
            expected_total=expected_total,
            expected_page_size=expected_page_size,
        )
        if expected_total is None:
            expected_total, expected_page_size = total, page_size
        issues.extend(
            {
                "rule": issue["rule"],
                "line": issue.get("line"),
                "message": issue.get("message", ""),
                "file": issue["component"].rsplit("/", 1)[-1],
            }
            for issue in page_issues
        )
        if done:
            break
        page += 1
    return issues


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(fetch(args.component), indent=1) + "\n")
