#!/usr/bin/env python3
"""Run exact Sonar C# Roslyn analyzer assemblies without a SonarQube server.

This covers diagnostics emitted by the Community compiler analyzer. Server-side
sensors and richer project integrations require a Community server scan.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote, urlparse

from csharp_oracle import generate_solution, is_sonar_rule_id
from parity import (
    input_paths_sha256,
    load_infra_boundaries,
    read_json,
    write_json_atomic,
)


REPO = Path(__file__).resolve().parent.parent.parent
DEFAULT_SOURCE = REPO / ".oracle/sonar/projects/oracle-cs"
DEFAULT_CATALOG = REPO / "catalog/rules/csharp.json"
BUILD_TIMEOUT_SECONDS = 1800


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def catalog_rule_ids(path: Path) -> list[str]:
    catalog = read_json(path)
    if not isinstance(catalog, dict) or not isinstance(catalog.get("rules"), list):
        raise ValueError("C# catalog must contain a rules list")
    rule_ids = []
    for index, rule in enumerate(catalog["rules"]):
        if not isinstance(rule, dict):
            raise ValueError(f"C# catalog rule {index} must be an object")
        key = rule.get("external_key")
        if not isinstance(key, str) or not key.startswith("csharpsquid:"):
            raise ValueError(
                f"C# catalog rule {index} must have a csharpsquid external key"
            )
        rule_id = key.removeprefix("csharpsquid:")
        if not is_sonar_rule_id(rule_id):
            raise ValueError(f"invalid C# catalog rule ID: {rule_id}")
        rule_ids.append(rule_id)
    if not rule_ids:
        raise ValueError("C# catalog must not be empty")
    if len(rule_ids) != len(set(rule_ids)):
        raise ValueError("C# catalog contains duplicate rule IDs")
    return sorted(rule_ids)


def _message_text(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and isinstance(value.get("text"), str):
        return value["text"]
    return None


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


def _sarif_issue(result: dict[str, Any]) -> dict[str, Any] | None:
    rule = result.get("ruleId")
    if not is_sonar_rule_id(rule):
        return None
    assert isinstance(rule, str)
    located = _location(result)
    if located is None:
        raise ValueError(f"SARIF result {rule} must contain a primary location")
    uri, region = located
    file_name = _file_name(uri)
    if file_name == "OracleStubs.g.cs":
        return None
    if not file_name:
        raise ValueError(f"SARIF result {rule} location must name a file")
    message = _message_text(result.get("message"))
    if message is None:
        raise ValueError(f"SARIF result {rule} message must contain text")
    start_line = region.get("startLine")
    start_column = region.get("startColumn")
    end_line = region.get("endLine", start_line)
    end_column = region.get("endColumn")
    if not all(
        isinstance(value, int) and not isinstance(value, bool)
        for value in (start_line, start_column, end_line, end_column)
    ):
        raise ValueError(f"SARIF result {rule} range must contain integer coordinates")
    if min(start_line, start_column, end_line, end_column) < 1:
        raise ValueError(f"SARIF result {rule} coordinates must be positive")
    if (start_line, start_column) > (end_line, end_column):
        raise ValueError(f"SARIF result {rule} range ends before it starts")
    return {
        "rule": f"csharpsquid:{rule}",
        "file": file_name,
        "message": message,
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


def _sarif_results(report: Any) -> Iterable[dict[str, Any]]:
    if not isinstance(report, dict):
        raise ValueError("SARIF report must be an object")
    runs = report.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ValueError("SARIF report must contain a non-empty runs list")
    for run_index, run in enumerate(runs):
        if not isinstance(run, dict):
            raise ValueError(f"SARIF run {run_index} must be an object")
        results = run.get("results")
        if not isinstance(results, list):
            raise ValueError(f"SARIF run {run_index} must contain a results list")
        for result_index, result in enumerate(results):
            if not isinstance(result, dict):
                raise ValueError(
                    f"SARIF run {run_index} result {result_index} must be an object"
                )
            yield result


def sarif_issues(
    paths: Iterable[Path],
    *,
    allowed_rule_ids: Iterable[str] | None = None,
    unlocated_rule_ids: Iterable[str] = (),
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    allowed = set(allowed_rule_ids) if allowed_rule_ids is not None else None
    unlocated = set(unlocated_rule_ids)
    if allowed is not None and not unlocated <= allowed:
        raise ValueError("unlocated C# rule allowlist must be within catalog scope")
    for path in sorted(paths):
        issues.extend(_sarif_path_issues(path, allowed, unlocated))
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


def _sarif_path_issues(
    path: Path, allowed: set[str] | None, unlocated: set[str]
) -> list[dict[str, Any]]:
    try:
        report = read_json(path)
        issues = []
        for result in _sarif_results(report):
            raw_rule_id = result.get("ruleId")
            if is_sonar_rule_id(raw_rule_id):
                assert isinstance(raw_rule_id, str)
                if allowed is not None and raw_rule_id not in allowed:
                    raise ValueError(
                        f"SARIF result {raw_rule_id} is absent from C# catalog"
                    )
                if _location(result) is None and raw_rule_id in unlocated:
                    if _message_text(result.get("message")) is None:
                        raise ValueError(
                            f"SARIF result {raw_rule_id} message must contain text"
                        )
                    continue
            issue = _sarif_issue(result)
            if issue is None:
                continue
            issues.append(issue)
        return issues
    except ValueError as error:
        raise ValueError(f"invalid SARIF report {path}: {error}") from error


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
    try:
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
            timeout=BUILD_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("native target build timed out") from error
    print(
        f"native target build: {fixture_count} isolated fixture project(s), exit {build.returncode}"
    )
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
        "oracle_evidence": {
            "project": "oracle-cs",
            "kind": "sq",
            "input_sha256": input_paths_sha256(REPO, [source, catalog]),
        },
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
        "issues": sarif_issues(
            sarif_paths,
            allowed_rule_ids=rule_ids,
            unlocated_rule_ids={
                key.removeprefix("csharpsquid:")
                for key in load_infra_boundaries(REPO / "catalog/infra-boundaries.json")
                if key.startswith("csharpsquid:")
            },
        ),
    }
    write_json_atomic(result, report, indent=1)
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
    except (OSError, ValueError, RuntimeError) as error:
        print(f"direct C# oracle failed: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
