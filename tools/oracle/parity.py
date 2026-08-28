"""Pure, strict SonarQube oracle comparison primitives.

The comparator deliberately treats parity as equality, not "both analyzers found
something somewhere in the file".  One finding is identified by its rule, file,
message, and complete primary range.  Any missing, extra, or differently located
finding is a divergence.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Callable, Iterable


ORACLE_REPORT_SCHEMA = 2
NON_FAILURE_STATUSES = frozenset(
    {"PASS", "ENTERPRISE_UNVERIFIED", "UPSTREAM_UNVERIFIED"}
)


def validate_oracle_report(report: Any) -> list[dict[str, Any]]:
    """Return issues from a complete v2 oracle artifact or reject weak evidence."""
    if not isinstance(report, dict) or report.get("schema_version") != ORACLE_REPORT_SCHEMA:
        raise ValueError(
            f"oracle report schema {ORACLE_REPORT_SCHEMA} required; rerun the SonarQube scan"
        )
    issues = report.get("issues")
    if not isinstance(issues, list):
        raise ValueError("oracle report issues must be a list")
    return issues


def _canonical_range(value: Any) -> tuple[int | None, int | None, int | None, int | None]:
    if not isinstance(value, dict):
        return (None, None, None, None)
    start = value.get("start")
    end = value.get("end")
    if not isinstance(start, dict) or not isinstance(end, dict):
        return (None, None, None, None)
    canonical = (
        start.get("line"),
        start.get("column"),
        end.get("line"),
        end.get("column"),
    )
    if canonical == (0, 0, 0, 0):
        return (None, None, None, None)
    return canonical


def _finding(
    *, rule: Any, file: Any, message: Any, range_value: Any
) -> tuple[str, str, str, int | None, int | None, int | None, int | None]:
    start_line, start_column, end_line, end_column = _canonical_range(range_value)
    return (
        str(rule or ""),
        str(file or ""),
        str(message or ""),
        start_line,
        start_column,
        end_line,
        end_column,
    )


def sonar_findings(report: Any) -> list[tuple[Any, ...]]:
    return [
        _finding(
            rule=issue.get("rule"),
            file=issue.get("file"),
            message=issue.get("message"),
            range_value=issue.get("range"),
        )
        for issue in validate_oracle_report(report)
        if isinstance(issue, dict)
    ]


def hoonarqube_findings(report: Any) -> list[tuple[Any, ...]]:
    if not isinstance(report, dict) or not isinstance(report.get("files"), list):
        raise ValueError("hoonarqube report must contain a files list")
    findings: list[tuple[Any, ...]] = []
    for file_report in report["files"]:
        if not isinstance(file_report, dict):
            raise ValueError("hoonarqube file report must be an object")
        path = str(file_report.get("path", ""))
        file_name = path.replace("\\", "/").rsplit("/", 1)[-1]
        issues = file_report.get("issues")
        if not isinstance(issues, list):
            raise ValueError("hoonarqube file issues must be a list")
        for issue in issues:
            if not isinstance(issue, dict):
                raise ValueError("hoonarqube issue must be an object")
            findings.append(
                _finding(
                    rule=issue.get("rule_key"),
                    file=file_name,
                    message=issue.get("message"),
                    range_value=issue.get("range"),
                )
            )
    return findings


def _for_file_rule(
    findings: Iterable[tuple[Any, ...]], file_name: str, rule: str
) -> Counter[tuple[Any, ...]]:
    return Counter(finding for finding in findings if finding[0] == rule and finding[1] == file_name)


def _serializable(counter: Counter[tuple[Any, ...]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for finding, count in sorted(counter.items(), key=repr):
        _, _, message, start_line, start_column, end_line, end_column = finding
        rows.append(
            {
                "message": message,
                "range": {
                    "start": {"line": start_line, "column": start_column},
                    "end": {"line": end_line, "column": end_column},
                },
                "count": count,
            }
        )
    return rows


def compare_reports(
    expected: list[dict[str, Any]],
    sonar_report: Any,
    hoonarqube_report: Any,
    infra: Iterable[str] = (),
    catalog_keys: Iterable[str] | None = None,
    available_files: Iterable[str] | None = None,
    enterprise_unverified: Iterable[str] = (),
) -> list[dict[str, Any]]:
    """Compare the complete catalog contract with exact finding equality."""
    sonar = sonar_findings(sonar_report)
    ours = hoonarqube_findings(hoonarqube_report)
    infra = set(infra)
    catalog = set(catalog_keys) if catalog_keys is not None else None
    files = set(available_files) if available_files is not None else None
    enterprise_unverified = set(enterprise_unverified)
    seen: set[str] = set()
    rows: list[dict[str, Any]] = []

    for expectation in expected:
        key = expectation.get("key")
        if not isinstance(key, str) or not key:
            rows.append({"key": key, "status": "INVALID_EXPECTATION", "reason": "missing key"})
            continue
        if key in seen:
            rows.append(
                {"key": key, "status": "INVALID_EXPECTATION", "reason": "duplicate key"}
            )
            continue
        seen.add(key)
        if catalog is not None and key not in catalog:
            rows.append(
                {
                    "key": key,
                    "status": "INVALID_EXPECTATION",
                    "reason": "expectation key is absent from frozen catalog",
                }
            )
            continue
        if key in infra or expectation.get("infra"):
            rows.append(
                {
                    "key": key,
                    "status": "INFRA",
                    "reason": str(
                        expectation.get(
                            "infra", "upstream analysis infrastructure required"
                        )
                    ),
                }
            )
            continue
        if expectation.get("skip"):
            rows.append(
                {"key": key, "status": "SKIPPED", "reason": str(expectation["skip"])}
            )
            continue

        bad = expectation.get("bad")
        if not isinstance(bad, str) or not bad:
            rows.append(
                {"key": key, "status": "INVALID_EXPECTATION", "reason": "missing bad file"}
            )
            continue
        good = expectation.get("good")
        if good is None:
            good = bad.replace("_bad", "_good")
        if not isinstance(good, str) or not good or good == bad:
            rows.append(
                {"key": key, "status": "INVALID_EXPECTATION", "reason": "missing good file"}
            )
            continue
        if files is not None and bad not in files:
            rows.append(
                {
                    "key": key,
                    "status": "INVALID_EXPECTATION",
                    "reason": f"bad fixture does not exist: {bad}",
                }
            )
            continue
        if files is not None and good not in files:
            rows.append(
                {
                    "key": key,
                    "status": "INVALID_EXPECTATION",
                    "reason": f"good fixture does not exist: {good}",
                }
            )
            continue

        minimum = expectation.get("expect_lines_min", 1)
        if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 1:
            rows.append(
                {"key": key, "status": "INVALID_EXPECTATION", "reason": "invalid minimum"}
            )
            continue

        upstream_unverified = expectation.get("upstream_unverified")
        if upstream_unverified is not None and (
            not isinstance(upstream_unverified, str) or not upstream_unverified.strip()
        ):
            rows.append(
                {
                    "key": key,
                    "status": "INVALID_EXPECTATION",
                    "reason": "invalid upstream-unverified reason",
                }
            )
            continue

        sonar_bad = _for_file_rule(sonar, bad, key)
        ours_bad = _for_file_rule(ours, bad, key)
        sonar_good = _for_file_rule(sonar, good, key)
        ours_good = _for_file_rule(ours, good, key)

        if upstream_unverified:
            if ours_good:
                status = "GOOD_FIRE"
            elif sum(ours_bad.values()) < minimum:
                status = "OURS_MISS"
            else:
                status = "UPSTREAM_UNVERIFIED"
        elif key in enterprise_unverified:
            if ours_good:
                status = "GOOD_FIRE"
            elif sum(ours_bad.values()) < minimum:
                status = "OURS_MISS"
            else:
                status = "ENTERPRISE_UNVERIFIED"
        elif sonar_good or ours_good:
            status = "GOOD_FIRE"
        elif sum(sonar_bad.values()) < minimum and sum(ours_bad.values()) < minimum:
            status = "BOTH_MISS"
        elif sum(sonar_bad.values()) < minimum:
            status = "SQ_MISS"
        elif sum(ours_bad.values()) < minimum:
            status = "OURS_MISS"
        elif sonar_bad != ours_bad:
            status = "BAD_MISMATCH"
        else:
            status = "PASS"

        rows.append(
            {
                "key": key,
                "status": status,
                "bad": bad,
                "good": good,
                "sonar_bad": _serializable(sonar_bad),
                "ours_bad": _serializable(ours_bad),
                "sonar_good": _serializable(sonar_good),
                "ours_good": _serializable(ours_good),
                **(
                    {"reason": str(upstream_unverified)}
                    if upstream_unverified
                    else {}
                ),
            }
        )
    if catalog is not None:
        for key in sorted(catalog - seen):
            rows.append(
                {
                    "key": key,
                    "status": "INVALID_EXPECTATION",
                    "reason": "catalog key has no oracle expectation",
                }
            )
    return rows


def counts(rows: Iterable[dict[str, Any]]) -> dict[str, int]:
    return dict(sorted(Counter(str(row.get("status", "UNKNOWN")) for row in rows).items()))


def failure_count(rows: Iterable[dict[str, Any]]) -> int:
    return sum(row.get("status") not in NON_FAILURE_STATUSES for row in rows)


def classify_sq_misses(
    rows: Iterable[dict[str, Any]],
    rule_available: Callable[[str], bool | None],
) -> tuple[list[str], list[str]]:
    """Classify Sonar misses without ever turning unverified parity green."""
    beyond: list[str] = []
    unverified: list[str] = []
    for row in rows:
        if row.get("status") not in {"SQ_MISS", "BOTH_MISS"}:
            continue
        key = row.get("key")
        if not isinstance(key, str):
            continue
        available = rule_available(key)
        if available is False:
            row["status"] = "BEYOND_CE"
            beyond.append(key)
        elif available is None:
            row["status"] = "ORACLE_UNVERIFIED"
            unverified.append(key)
    return beyond, unverified


def parse_report_task(text: str) -> dict[str, str]:
    task = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    if not task.get("ceTaskId"):
        raise ValueError("report-task.txt lacks ceTaskId")
    return task


def wait_for_compute_engine(
    task_id: str,
    fetch_status: Callable[[str], str | None],
    pause: Callable[[], None],
    attempts: int = 120,
) -> str:
    """Wait until SonarQube Compute Engine commits the submitted analysis."""
    for _ in range(attempts):
        status = fetch_status(task_id)
        if status in {"SUCCESS", "FAILED", "CANCELED"}:
            return status
        pause()
    return "TIMEOUT"
