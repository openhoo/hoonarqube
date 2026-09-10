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
    canonical_sonar_security_issue,
    parse_json,
    read_secret_file,
    validate_search_page,
    validate_security_evidence,
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
                "additionalFields": "_all",
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


def _security_request(
    component: str,
    *,
    hotspot: bool,
    rule: str | None,
    page: int,
    authorization: str,
) -> tuple[urllib.request.Request, str]:
    item_key = "hotspots" if hotspot else "issues"
    if hotspot:
        params = {"projectKey": component, "ps": 500, "p": page}
        path = "/api/hotspots/search"
    else:
        params = {
            "componentKeys": component,
            "resolved": "false",
            "additionalFields": "_all",
            "ps": 500,
            "p": page,
            "s": "FILE_LINE",
            "asc": "true",
        }
        if rule is not None:
            params["rules"] = rule
        path = "/api/issues/search"
    query = urllib.parse.urlencode(params)
    request = urllib.request.Request(f"{BASE}{path}?{query}")
    request.add_header("Authorization", authorization)
    return request, item_key


def _security_limits(findings: list[dict[str, object]]) -> list[str]:
    limits = []
    for finding in findings:
        detector = finding["detector"]
        if not detector["flow_evidence_available"]:
            limits.append(f"{finding['rule']}:flow-evidence-unavailable")
        if not detector["secondary_location_evidence_available"]:
            limits.append(f"{finding['rule']}:secondary-location-evidence-unavailable")
        if not detector["primary_range_evidence_available"]:
            limits.append(f"{finding['rule']}:primary-range-evidence-unavailable")
    return sorted(set(limits))


def fetch_security(
    component: str,
    *,
    hotspot: bool = False,
    edition: str = "community",
    rule: str | None = None,
) -> dict[str, object]:
    """Fetch strict detector evidence, retaining explicit unavailable limits."""
    if not isinstance(component, str) or not component:
        raise ValueError("security component must be a non-empty string")
    if not isinstance(edition, str) or edition.strip().lower() != "community":
        raise ValueError(
            "fetch_security only certifies community; enterprise requires "
            "independent licensed server evidence"
        )
    if rule is not None and (not isinstance(rule, str) or not rule.strip()):
        raise ValueError("security rule must be a non-empty string when provided")
    findings: list[dict[str, object]] = []
    page = 1
    expected_total = expected_page_size = None
    seen_keys: set[str] = set()
    authorization = auth_header()
    while True:
        request, item_key = _security_request(
            component,
            hotspot=hotspot,
            rule=rule,
            page=page,
            authorization=authorization,
        )
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            payload = parse_json(
                response.read().decode("utf-8"),
                context=f"Sonar {item_key} API JSON",
            )
        items, total, page_size, done = validate_search_page(
            payload,
            item_key,
            page,
            expected_total=expected_total,
            expected_page_size=expected_page_size,
            seen_keys=seen_keys,
        )
        if expected_total is None:
            expected_total, expected_page_size = total, page_size
        findings.extend(
            canonical_sonar_security_issue(
                item,
                hotspot=hotspot,
                expected_project=component,
            )
            for item in items
        )
        if done:
            break
        page += 1
    artifact = {
        "schema_version": 1,
        "project": component,
        "source": "sonarqube",
        "edition": edition,
        "sensor": {
            "kind": "security-hotspot" if hotspot else "issue",
            "endpoint": "/api/hotspots/search" if hotspot else "/api/issues/search",
        },
        "findings": findings,
        "limits": _security_limits(findings),
    }
    validate_security_evidence(artifact, expected_project=component)
    return artifact


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    write_json_atomic(args.output, fetch(args.component), indent=1)
