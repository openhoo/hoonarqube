#!/usr/bin/env python3
"""Verify Hoonarqube's current Generic Issue Import against a live SonarQube."""

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

from parity import parse_report_task, wait_for_compute_engine


REPO = Path(__file__).resolve().parent.parent.parent
SOURCE = Path("tools/oracle/fixtures/import-smoke/src/sample.py")
RULE = "external_hoonarqube:python:S112"
MESSAGE = "Replace this generic exception class with a more specific one."
HTTP_TIMEOUT_SECONDS = 30


def request_json(url: str, token: str, path: str, params=None):
    query = "?" + urllib.parse.urlencode(params) if params else ""
    request = urllib.request.Request(url.rstrip("/") + path + query)
    encoded = base64.b64encode(f"{token}:".encode()).decode()
    request.add_header("Authorization", f"Basic {encoded}")
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
        return json.load(response)


def verify_imported_issue(payload):
    issues = payload.get("issues") if isinstance(payload, dict) else None
    if not isinstance(issues, list):
        raise ValueError("issues response lacks issues list")
    matches = [issue for issue in issues if issue.get("rule") == RULE]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one {RULE} issue, got {len(matches)}")
    issue = matches[0]
    expected_range = {
        "startLine": 2,
        "endLine": 2,
        "startOffset": 10,
        "endOffset": 39,
    }
    if issue.get("message") != MESSAGE:
        raise ValueError("imported issue message differs")
    if issue.get("textRange") != expected_range:
        raise ValueError("imported issue range differs")
    return issue


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sonar-url",
        default=os.environ.get("SONAR_IMPORT_URL", "http://127.0.0.1:19000"),
    )
    parser.add_argument("--token", default=os.environ.get("SONAR_IMPORT_TOKEN"))
    parser.add_argument(
        "--scanner",
        default=os.environ.get(
            "SONAR_SCANNER",
            "/tmp/sonar-scanner-6.2.1.4610-linux-x64/bin/sonar-scanner",
        ),
    )
    parser.add_argument("--project", default="hoonarqube-import-smoke")
    args = parser.parse_args()
    if not args.token:
        parser.error("pass --token or set SONAR_IMPORT_TOKEN")

    subprocess.run(
        ["cargo", "build", "-q", "-p", "hoonarqube-cli"], cwd=REPO, check=True
    )
    with tempfile.TemporaryDirectory(prefix="hoonarqube-import-smoke-") as temp:
        temp_path = Path(temp)
        report = temp_path / "report.json"
        scanner_work = temp_path / "scanner"
        with report.open("w") as output:
            subprocess.run(
                [
                    str(REPO / "target/debug/hoonarqube"),
                    "analyze",
                    "--format",
                    "sonar",
                    str(SOURCE),
                ],
                cwd=REPO,
                stdout=output,
                check=True,
            )
        generated = json.loads(report.read_text())
        if not isinstance(generated.get("rules"), list) or not isinstance(
            generated.get("issues"), list
        ):
            raise SystemExit(
                "generated report does not use current rules/issues schema"
            )

        subprocess.run(
            [
                args.scanner,
                f"-Dsonar.projectKey={args.project}",
                f"-Dsonar.projectName={args.project}",
                f"-Dsonar.sources={SOURCE.parent}",
                f"-Dsonar.externalIssuesReportPaths={report}",
                f"-Dsonar.host.url={args.sonar_url}",
                f"-Dsonar.token={args.token}",
                f"-Dsonar.working.directory={scanner_work}",
            ],
            cwd=REPO,
            check=True,
        )
        task_id = parse_report_task((scanner_work / "report-task.txt").read_text())[
            "ceTaskId"
        ]
        status = wait_for_compute_engine(
            task_id,
            lambda value: (
                request_json(args.sonar_url, args.token, "/api/ce/task", {"id": value})
                .get("task", {})
                .get("status")
            ),
            lambda: time.sleep(1),
        )
        if status != "SUCCESS":
            raise SystemExit(f"SonarQube Compute Engine finished with {status}")

        payload = request_json(
            args.sonar_url,
            args.token,
            "/api/issues/search",
            {"componentKeys": args.project, "ps": 100},
        )
        issue = verify_imported_issue(payload)
        print(
            json.dumps(
                {
                    "server": request_json(
                        args.sonar_url, args.token, "/api/system/status"
                    ).get("version"),
                    "project": args.project,
                    "rule": issue["rule"],
                    "message": issue["message"],
                    "textRange": issue["textRange"],
                    "status": "PASS",
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
