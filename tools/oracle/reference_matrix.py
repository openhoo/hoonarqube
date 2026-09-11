#!/usr/bin/env python3
"""Build a complete, reference-only oracle matrix.

A Sonar-only run cannot claim native parity.  This artifact therefore keeps
all expected rows and the complete Sonar finding multisets, records an explicit
reference status, and marks the native comparison ``DEFERRED``.  Main can run
the emitted exact ``diff.py`` command after producing a provenance-bound native
artifact.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping

from parity import (
    load_infra_boundaries,
    read_jsonl,
    validate_oracle_report,
    write_json_atomic,
)

SCHEMA_VERSION = 1


def _finding_identity(issue: Mapping[str, Any]) -> tuple[Any, ...]:
    value = issue.get("range")
    if value is None:
        range_key = (None, None, None, None)
    else:
        start = value["start"]
        end = value["end"]
        range_key = (
            start["line"],
            start["column"],
            end["line"],
            end["column"],
        )
    return (
        issue["rule"],
        issue["file"],
        issue["message"],
        *range_key,
    )


def _finding_json(identity: tuple[Any, ...]) -> dict[str, Any]:
    rule, file_name, message, start_line, start_column, end_line, end_column = identity
    row: dict[str, Any] = {
        "rule": rule,
        "file": file_name,
        "message": message,
        "range": None,
    }
    if start_line is not None:
        row["range"] = {
            "start": {"line": start_line, "column": start_column},
            "end": {"line": end_line, "column": end_column},
        }
    return row


def _multiset(issues: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    counts = Counter(_finding_identity(issue) for issue in issues)
    return [
        {**_finding_json(identity), "count": count}
        for identity, count in sorted(counts.items(), key=repr)
    ]


def _expectation_error(key: Any, reason: str) -> dict[str, Any]:
    return {
        "key": key,
        "status": "INVALID_EXPECTATION",
        "reference_status": "INVALID_EXPECTATION",
        "native_status": "NOT_APPLICABLE",
        "reason": reason,
    }


def _validated_expectation_key(
    raw: Any, catalog: set[str]
) -> tuple[str | None, dict[str, Any] | None]:
    if not isinstance(raw, dict):
        return None, _expectation_error(None, "expectation must be an object")
    key = raw.get("key")
    if not isinstance(key, str) or not key:
        return None, _expectation_error(key, "missing key")
    if key not in catalog:
        return None, _expectation_error(
            key, "expectation key is absent from frozen catalog"
        )
    return key, None


def _deferred_expectation(
    key: str, *, infra: str | None = None, skip: str | None = None
) -> dict[str, Any]:
    return {
        "key": key,
        "bad": None,
        "good": None,
        "minimum": 0,
        "upstream_unverified": None,
        "infra": infra,
        "skip": skip,
    }


def _validate_declared_defer(
    raw: dict[str, Any],
    key: str,
    infra_boundaries: Mapping[str, str],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    declared_infra = raw.get("infra")
    if declared_infra is not None:
        if not isinstance(declared_infra, str) or not declared_infra.strip():
            return None, _expectation_error(key, "invalid infrastructure reason")
        if infra_boundaries.get(key) != declared_infra:
            return None, _expectation_error(
                key, "infrastructure reason does not match approved boundary"
            )
        return _deferred_expectation(key, infra=declared_infra), None
    declared_skip = raw.get("skip")
    if declared_skip is not None:
        if not isinstance(declared_skip, str) or not declared_skip.strip():
            return None, _expectation_error(key, "invalid skip reason")
        return _deferred_expectation(key, skip=declared_skip), None
    return None, None


def _validate_expectation_files(
    raw: dict[str, Any], key: str, available: set[str]
) -> tuple[tuple[str, str] | None, dict[str, Any] | None]:
    bad = raw.get("bad")
    if not isinstance(bad, str) or not bad:
        return None, _expectation_error(key, "missing bad file")
    good = raw.get("good") or (
        bad.replace("_bad", "_good") if isinstance(bad, str) else None
    )
    if not isinstance(good, str) or not good or good == bad:
        return None, _expectation_error(key, "missing good file")
    if bad not in available:
        return None, _expectation_error(key, f"bad fixture does not exist: {bad}")
    if good not in available:
        return None, _expectation_error(key, f"good fixture does not exist: {good}")
    return (bad, good), None


def _validate_expectation_minimum(
    raw: dict[str, Any], key: str
) -> tuple[int | None, dict[str, Any] | None]:
    minimum = raw.get("expect_lines_min", 1)
    if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 1:
        return None, _expectation_error(key, "invalid minimum")
    return minimum, None


def _validate_expectation_upstream(
    raw: dict[str, Any], key: str
) -> tuple[str | None, dict[str, Any] | None]:
    upstream = raw.get("upstream_unverified")
    if upstream is not None and (not isinstance(upstream, str) or not upstream.strip()):
        return None, _expectation_error(key, "invalid upstream-unverified reason")
    return upstream, None


def _validate_expectation(
    raw: Any,
    available: set[str],
    catalog: set[str],
    infra_boundaries: Mapping[str, str],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    key, terminal = _validated_expectation_key(raw, catalog)
    if terminal is not None:
        return None, terminal
    assert key is not None
    deferred, terminal = _validate_declared_defer(raw, key, infra_boundaries)
    if deferred is not None or terminal is not None:
        return deferred, terminal
    fixtures, terminal = _validate_expectation_files(raw, key, available)
    if terminal is not None:
        return None, terminal
    assert fixtures is not None
    minimum, terminal = _validate_expectation_minimum(raw, key)
    if terminal is not None:
        return None, terminal
    assert minimum is not None
    upstream, terminal = _validate_expectation_upstream(raw, key)
    if terminal is not None:
        return None, terminal
    return {
        "key": key,
        "bad": fixtures[0],
        "good": fixtures[1],
        "minimum": minimum,
        "upstream_unverified": upstream,
        "infra": None,
        "skip": None,
    }, None


def _findings_by_rule(
    issues: Iterable[Mapping[str, Any]],
) -> dict[str, list[Mapping[str, Any]]]:
    by_rule: dict[str, list[Mapping[str, Any]]] = {}
    for issue in issues:
        by_rule.setdefault(str(issue["rule"]), []).append(issue)
    return by_rule


def _partition_reference_findings(
    rule_issues: list[Mapping[str, Any]], item: Mapping[str, Any]
) -> tuple[
    list[Mapping[str, Any]],
    list[Mapping[str, Any]],
    list[Mapping[str, Any]],
]:
    bad_file = item["bad"]
    good_file = item["good"]
    bad = [issue for issue in rule_issues if issue["file"] == bad_file]
    good = [issue for issue in rule_issues if issue["file"] == good_file]
    other = [
        issue for issue in rule_issues if issue["file"] not in {bad_file, good_file}
    ]
    return bad, good, other


def _reference_status_reason(
    key: str,
    item: Mapping[str, Any],
    bad: list[Mapping[str, Any]],
    good: list[Mapping[str, Any]],
    enterprise: set[str],
) -> tuple[str, str]:
    if item["upstream_unverified"]:
        return "UPSTREAM_UNVERIFIED", item["upstream_unverified"]
    if key in enterprise:
        return (
            "ENTERPRISE_UNVERIFIED",
            "Community reference cannot certify enterprise analyzer behavior",
        )
    if good:
        return "GOOD_FIRE", "reference finding on good fixture"
    if len(bad) < item["minimum"]:
        return (
            "SQ_MISS",
            "reference analyzer emitted fewer findings than the expectation",
        )
    return (
        "REFERENCE_PRESENT",
        "reference analyzer emitted the expected bad-fixture minimum; "
        "native comparison deferred",
    )


def _reference_row(
    item: Mapping[str, Any],
    by_rule: Mapping[str, list[Mapping[str, Any]]],
    enterprise: set[str],
) -> dict[str, Any]:
    key = item["key"]
    if item["infra"] is not None or item["skip"] is not None:
        reference_status = "INFRA" if item["infra"] is not None else "SKIPPED"
        reason = item["infra"] or item["skip"]
        return {
            "key": key,
            "status": "DEFERRED",
            "reference_status": reference_status,
            "native_status": "DEFERRED",
            "reason": reason,
            "sonar_rule": _multiset(by_rule.get(key, [])),
        }
    bad, good, other = _partition_reference_findings(by_rule.get(key, []), item)
    status, reason = _reference_status_reason(key, item, bad, good, enterprise)
    return {
        "key": key,
        "bad": item["bad"],
        "good": item["good"],
        "minimum": item["minimum"],
        "status": "DEFERRED",
        "reference_status": status,
        "native_status": "DEFERRED",
        "reason": reason,
        "sonar_bad": _multiset(bad),
        "sonar_good": _multiset(good),
        "sonar_other": _multiset(other),
    }


def _expected_reference_rows(
    expected: list[Any],
    available: set[str],
    catalog: set[str],
    approved_infra: Mapping[str, str],
    by_rule: Mapping[str, list[Mapping[str, Any]]],
    enterprise: set[str],
) -> tuple[list[dict[str, Any]], set[str]]:
    rows: list[dict[str, Any]] = []
    declared: set[str] = set()
    for raw in expected:
        item, terminal = _validate_expectation(raw, available, catalog, approved_infra)
        if terminal is not None:
            rows.append(terminal)
            if isinstance(terminal.get("key"), str):
                declared.add(terminal["key"])
            continue
        assert item is not None
        key = item["key"]
        if key in declared:
            rows.append(_expectation_error(key, "duplicate key"))
            continue
        declared.add(key)
        rows.append(_reference_row(item, by_rule, enterprise))
    return rows, declared


def _new_upstream_rule_row(
    key: str, reason: str, sonar_bad: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "key": key,
        "status": "DEFERRED",
        "reference_status": "NEW_UPSTREAM_RULE",
        "native_status": "DEFERRED",
        "reason": reason,
        "sonar_bad": sonar_bad,
        "sonar_good": [],
        "sonar_other": [],
    }


def build_reference_rows(
    expected: list[Any],
    sonar_report: Mapping[str, Any],
    *,
    catalog_keys: Iterable[str],
    available_files: Iterable[str],
    enterprise_unverified: Iterable[str] = (),
    infra_boundaries: Mapping[str, str] | None = None,
    expected_project: str | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    issues = validate_oracle_report(
        sonar_report,
        expected_project=(
            expected_project
            if expected_project is not None
            else sonar_report.get("project")
        ),
    )
    by_rule = _findings_by_rule(issues)
    catalog = set(catalog_keys)
    available = set(available_files)
    enterprise = set(enterprise_unverified)
    approved_infra = dict(infra_boundaries or {})
    rows, declared = _expected_reference_rows(
        expected,
        available,
        catalog,
        approved_infra,
        by_rule,
        enterprise,
    )
    rows.extend(
        _new_upstream_rule_row(
            key,
            "catalog rule has no frozen oracle expectation",
            [],
        )
        for key in sorted(catalog - declared)
    )
    rows.extend(
        _new_upstream_rule_row(
            key,
            "Sonar emitted a rule absent from the frozen catalog",
            _multiset(by_rule[key]),
        )
        for key in sorted(set(by_rule) - catalog)
    )
    return rows, _multiset(issues)


def build_reference_report(
    *,
    project: str,
    language: str,
    project_dir: Path,
    sonar_report: Mapping[str, Any],
    provenance: Mapping[str, Any],
    catalog_keys: Iterable[str],
    enterprise_unverified: Iterable[str],
    compare_command: str,
    reference_command: str,
    sonar_artifact: str,
) -> dict[str, Any]:
    fixture_dir = project_dir if project == "oracle-cs" else project_dir / "src"
    extension = {
        "python": {".py"},
        "javascript": {".js", ".jsx"},
        "typescript": {".ts", ".tsx"},
        "csharp": {".cs"},
        "go": {".go"},
        "rust": {".rs"},
    }[language]
    source_files = [
        path
        for path in fixture_dir.rglob("*")
        if path.is_file() and path.suffix in extension
    ]
    available = [path.name for path in source_files]
    if len(available) != len(set(available)):
        raise ValueError("fixture inventory contains duplicate basenames")
    available.sort()
    expected = read_jsonl(project_dir / "expected.jsonl")
    infra_boundaries = load_infra_boundaries(
        Path(__file__).resolve().parents[2] / "catalog/infra-boundaries.json"
    )
    project_findings = sonar_report.get("project_issues", [])
    if not isinstance(project_findings, list):
        raise ValueError("oracle project_issues must be a list")
    if project_findings and project != "oracle-cs":
        raise ValueError("non-C# artifact contains project-level findings")
    seen_project_keys: set[str] = set()
    for finding in project_findings:
        if (
            not isinstance(finding, dict)
            or finding.get("kind") != "PROJECT_LEVEL"
            or not all(
                isinstance(finding.get(field), str) and finding[field]
                for field in ("key", "rule", "message", "component")
            )
            or finding["component"] != project
            or finding["rule"] not in infra_boundaries
            or finding["key"] in seen_project_keys
            or any(
                field in finding
                and finding[field] is not None
                and not isinstance(finding[field], str)
                for field in ("severity", "type")
            )
        ):
            raise ValueError("invalid project-level oracle finding")
        seen_project_keys.add(finding["key"])
    rows, all_findings = build_reference_rows(
        expected,
        sonar_report,
        catalog_keys=catalog_keys,
        available_files=available,
        enterprise_unverified=enterprise_unverified,
        infra_boundaries=infra_boundaries,
        expected_project=project,
    )
    status_counts = Counter(str(row.get("reference_status", "UNKNOWN")) for row in rows)
    if project_findings:
        status_counts["PROJECT_LEVEL_FINDINGS"] = len(project_findings)
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "reference_matrix",
        "project": project,
        "language": language,
        "projects": [project],
        "reference_only": True,
        "native_status": "DEFERRED",
        "provenance": provenance,
        "sonar_artifact": sonar_artifact,
        "sonar_findings": all_findings,
        "sonar_project_findings": project_findings,
        "rows": rows,
        "summary": dict(sorted(status_counts.items())),
        "compare_command": compare_command,
        "reference_command": reference_command,
        "commands": {
            "native_compare": compare_command,
            "reference_scan": reference_command,
        },
    }


def write_reference_report(path: Path, report: Mapping[str, Any]) -> None:
    write_json_atomic(path, dict(report), indent=1)
