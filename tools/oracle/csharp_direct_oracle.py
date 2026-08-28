#!/usr/bin/env python3
"""Run exact Sonar C# Roslyn analyzer assemblies without a SonarQube server.

This covers diagnostics emitted by the Community compiler analyzer. Server-side
sensors and richer project integrations require a Community server scan.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote, urlparse

from csharp_oracle import generate_solution


REPO = Path(__file__).resolve().parent.parent.parent
DEFAULT_SOURCE = REPO / ".oracle/sonar/projects/oracle-cs"
DEFAULT_CATALOG = REPO / "catalog/rules/csharp.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def catalog_rule_ids(path: Path) -> list[str]:
    catalog = json.loads(path.read_text())
    return sorted(
        {
            str(rule["external_key"]).rsplit(":", 1)[-1]
            for rule in catalog.get("rules", [])
        }
    )


def _message_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and isinstance(value.get("text"), str):
        return value["text"]
    return ""


def _location(result: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        return None
    location = locations[0]
    if not isinstance(location, dict):
        return None

    # Roslyn currently writes its pre-standard SARIF shape. Also accept SARIF
    # 2.1 so SDK upgrades cannot silently erase oracle findings.
    result_file = location.get("resultFile")
    if isinstance(result_file, dict):
        uri = result_file.get("uri")
        region = result_file.get("region")
    else:
        physical = location.get("physicalLocation")
        if not isinstance(physical, dict):
            return None
        artifact = physical.get("artifactLocation")
        uri = artifact.get("uri") if isinstance(artifact, dict) else None
        region = physical.get("region")
    if not isinstance(uri, str) or not isinstance(region, dict):
        return None
    return uri, region


def _file_name(uri: str) -> str:
    parsed = urlparse(uri)
    path = parsed.path if parsed.scheme == "file" else uri
    return Path(unquote(path.replace("\\", "/"))).name


def sarif_issues(paths: Iterable[Path]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for path in sorted(paths):
        report = json.loads(path.read_text())
        for run in report.get("runs", []):
            if not isinstance(run, dict):
                continue
            for result in run.get("results", []):
                if not isinstance(result, dict):
                    continue
                rule = result.get("ruleId")
                if not isinstance(rule, str) or not rule.startswith("S"):
                    continue
                located = _location(result)
                if located is None:
                    continue
                uri, region = located
                file_name = _file_name(uri)
                if file_name == "OracleStubs.g.cs":
                    continue
                start_line = region.get("startLine")
                start_column = region.get("startColumn")
                end_line = region.get("endLine", start_line)
                end_column = region.get("endColumn")
                if not all(
                    isinstance(value, int)
                    for value in (start_line, start_column, end_line, end_column)
                ):
                    continue
                issues.append(
                    {
                        "rule": f"csharpsquid:{rule}",
                        "file": file_name,
                        "message": _message_text(result.get("message")),
                        "range": {
                            "start": {
                                "line": start_line,
                                "column": max(0, start_column - 1),
                            },
                            "end": {
                                "line": end_line,
                                "column": max(0, end_column - 1),
                            },
                        },
                        "hotspot": False,
                    }
                )
    return sorted(
        issues,
        key=lambda issue: (
            issue["rule"],
            issue["file"],
            issue["range"]["start"]["line"],
            issue["range"]["start"]["column"],
            issue["message"],
        ),
    )


def run(
    source: Path,
    analyzers: list[Path],
    catalog: Path,
    result: Path,
    workspace: Path,
    limit: int | None,
) -> dict[str, Any]:
    rule_ids = catalog_rule_ids(catalog)
    solution, fixture_count = generate_solution(
        source,
        workspace,
        limit=limit,
        analyzers=analyzers,
        enabled_rules=rule_ids,
        error_log="target.sarif",
    )
    build = subprocess.run(
        [
            "dotnet",
            "build",
            str(solution),
            "--no-incremental",
            "--disable-build-servers",
            "--verbosity:quiet",
        ],
        cwd=workspace,
        capture_output=True,
        text=True,
    )
    print(f"native target build: {fixture_count} isolated fixture project(s), exit {build.returncode}")
    if build.returncode != 0:
        output = (build.stdout + "\n" + build.stderr).strip()
        raise RuntimeError(f"native target build failed\n{output[-4000:]}")
    sarif_paths = list((workspace / "projects").glob("*/target.sarif"))
    if len(sarif_paths) != fixture_count:
        raise RuntimeError(
            f"expected {fixture_count} SARIF reports, found {len(sarif_paths)}"
        )
    report = {
        "schema_version": 2,
        "project": "oracle-cs",
        "server": {
            "kind": "direct-roslyn-analyzer",
            "limitations": [
                "server-side sensors excluded",
                "security hotspots excluded",
                "taint analysis excluded",
            ],
            "analyzers": [
                {
                    "name": path.name,
                    "sha256": sha256_file(path),
                }
                for path in analyzers
            ],
        },
        "issues": sarif_issues(sarif_paths),
    }
    result.parent.mkdir(parents=True, exist_ok=True)
    result.write_text(json.dumps(report, indent=1) + "\n")
    print(f"direct analyzer issues: {len(report['issues'])}")
    print(f"result: {result}")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analyzer", action="append", required=True, type=Path)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    if shutil.which("dotnet") is None:
        parser.error("dotnet SDK missing")
    analyzers = [path.resolve() for path in args.analyzer]
    try:
        if args.workspace:
            args.workspace.mkdir(parents=True, exist_ok=False)
            run(
                args.source.resolve(),
                analyzers,
                args.catalog.resolve(),
                args.result.resolve(),
                args.workspace.resolve(),
                args.limit,
            )
        else:
            with tempfile.TemporaryDirectory(
                prefix="direct-csharp-", dir=REPO / "tools/oracle"
            ) as directory:
                run(
                    args.source.resolve(),
                    analyzers,
                    args.catalog.resolve(),
                    args.result.resolve(),
                    Path(directory),
                    args.limit,
                )
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"direct C# oracle failed: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
