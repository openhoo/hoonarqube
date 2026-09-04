#!/usr/bin/env python3
"""Fetch all issues for one SonarQube project via pagination."""

import argparse
import base64
import os
import urllib.parse
import urllib.request
from pathlib import Path

from parity import (
    canonical_sonar_issue,
    parse_json,
    read_secret_file,
    validate_search_page,
    write_json_atomic,
)


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
        token = read_secret_file(token_path).strip()
    if not token:
        raise RuntimeError("SONAR_ORACLE_TOKEN must not be empty")
    encoded = base64.b64encode(f"{token}:".encode()).decode()
    return f"Basic {encoded}"


def fetch(component):
    """Return every normalized issue for `component` or reject weak paging."""
    issues, page = [], 1
    authorization = auth_header()
    expected_total = expected_page_size = None
    seen_keys = set()
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
            d = parse_json(
                response.read().decode("utf-8"), context="Sonar issues API JSON"
            )
        page_issues, total, page_size, done = validate_search_page(
            d,
            "issues",
            page,
            expected_total=expected_total,
            expected_page_size=expected_page_size,
            seen_keys=seen_keys,
        )
        if expected_total is None:
            expected_total, expected_page_size = total, page_size
        issues.extend(
            canonical_sonar_issue(issue, hotspot=False, expected_project=component)
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
    write_json_atomic(args.output, fetch(args.component), indent=1)
