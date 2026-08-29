"""Pure, strict SonarQube oracle comparison primitives.

The comparator deliberately treats parity as equality, not "both analyzers found
something somewhere in the file".  One finding is identified by its rule, file,
message, and complete primary range.  Any missing, extra, or differently located
finding is a divergence.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable, Iterable


ORACLE_REPORT_SCHEMA = 2
NON_FAILURE_STATUSES = frozenset(
    {"PASS", "ENTERPRISE_UNVERIFIED", "UPSTREAM_UNVERIFIED"}
)


def validate_oracle_report(
    report: Any, *, expected_project: str | None = None
) -> list[dict[str, Any]]:
    """Return issues from a complete v2 oracle artifact or reject weak evidence."""
    if (
        not isinstance(report, dict)
        or report.get("schema_version") != ORACLE_REPORT_SCHEMA
    ):
        raise ValueError(
            f"oracle report schema {ORACLE_REPORT_SCHEMA} required; "
            "rerun the SonarQube scan"
        )
    if expected_project is not None and report.get("project") != expected_project:
        raise ValueError(
            f"oracle report project must be {expected_project!r}; "
            f"got {report.get('project')!r}"
        )
    issues = report.get("issues")
    if not isinstance(issues, list):
        raise ValueError("oracle report issues must be a list")
    return issues


def validate_search_page(
    payload: Any,
    item_key: str,
    requested_page: int,
    *,
    expected_total: int | None = None,
    expected_page_size: int | None = None,
) -> tuple[list[Any], int, int, bool]:
    """Validate one Sonar search page and return items plus paging state."""
    if (
        not isinstance(requested_page, int)
        or isinstance(requested_page, bool)
        or requested_page < 1
    ):
        raise ValueError("requested page must be a positive integer")
    context = f"{item_key} page {requested_page}"
    if not isinstance(payload, dict):
        raise ValueError(f"{context} response must be an object")
    items = payload.get(item_key)
    if not isinstance(items, list):
        raise ValueError(f"{context} must contain a {item_key} list")
    malformed_index = next(
        (index for index, item in enumerate(items) if not isinstance(item, dict)),
        None,
    )
    if malformed_index is not None:
        raise ValueError(f"{context} item {malformed_index} must be an object")
    paging = payload.get("paging")
    if not isinstance(paging, dict):
        raise ValueError(f"{context} must contain a paging object")

    page_index, page_size, total = _validate_search_paging(
        paging,
        requested_page,
        expected_total,
        expected_page_size,
        context,
    )
    offset = (page_index - 1) * page_size
    if offset > total:
        raise ValueError(f"{context} starts beyond advertised total {total}")
    expected_count = min(page_size, total - offset)
    if len(items) != expected_count:
        raise ValueError(
            f"{context} returned {len(items)} items, expected {expected_count} "
            f"from advertised total {total}"
        )
    return items, total, page_size, offset + len(items) == total


def _validate_search_paging(
    paging: dict[str, Any],
    requested_page: int,
    expected_total: int | None,
    expected_page_size: int | None,
    context: str,
) -> tuple[int, int, int]:
    page_index = _required_paging_int(paging, "pageIndex", context)
    page_size = _required_paging_int(paging, "pageSize", context)
    total = _required_paging_int(paging, "total", context)
    if page_index != requested_page:
        raise ValueError(
            f"{context} returned pageIndex {page_index}, expected {requested_page}"
        )
    if page_size <= 0:
        raise ValueError(f"{context} pageSize must be positive")
    if total < 0:
        raise ValueError(f"{context} total must be non-negative")
    if expected_total is not None and total != expected_total:
        raise ValueError(f"{context} total changed from {expected_total} to {total}")
    if expected_page_size is not None and page_size != expected_page_size:
        raise ValueError(
            f"{context} pageSize changed from {expected_page_size} to {page_size}"
        )
    return page_index, page_size, total


def _required_paging_int(paging: dict[str, Any], key: str, context: str) -> int:
    value = paging.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{context} paging {key} must be an integer")
    return value


def _canonical_range(
    value: Any, *, context: str, allow_absent: bool
) -> tuple[int | None, int | None, int | None, int | None]:
    if value is None and allow_absent:
        return (None, None, None, None)
    if not isinstance(value, dict):
        raise ValueError(f"{context} range must be an object")
    start = value.get("start")
    end = value.get("end")
    if not isinstance(start, dict) or not isinstance(end, dict):
        raise ValueError(f"{context} range must contain start and end objects")
    canonical = (
        start.get("line"),
        start.get("column"),
        end.get("line"),
        end.get("column"),
    )
    if canonical == (0, 0, 0, 0):
        return (None, None, None, None)
    if canonical == (None, None, None, None):
        return canonical
    _validate_text_range(canonical, context)
    return canonical


def _validate_text_range(canonical: tuple[Any, ...], context: str) -> None:
    if any(coordinate is None for coordinate in canonical):
        raise ValueError(f"{context} range must be complete or file-level")
    for coordinate in canonical:
        if (
            not isinstance(coordinate, int)
            or isinstance(coordinate, bool)
            or coordinate < 0
        ):
            raise ValueError(
                f"{context} range coordinates must be non-negative integers or null"
            )
    start_line, start_column, end_line, end_column = canonical
    if start_line == 0 or end_line == 0:
        raise ValueError(f"{context} text range lines must be positive")
    if (start_line, start_column) > (end_line, end_column):
        raise ValueError(f"{context} range ends before it starts")


def _finding(
    *,
    rule: str,
    file: str,
    message: str,
    range_value: Any,
    context: str,
    allow_absent_range: bool,
) -> tuple[str, str, str, int | None, int | None, int | None, int | None]:
    start_line, start_column, end_line, end_column = _canonical_range(
        range_value, context=context, allow_absent=allow_absent_range
    )
    return (
        rule,
        file,
        message,
        start_line,
        start_column,
        end_line,
        end_column,
    )


def _required_string(value: dict[str, Any], key: str, context: str) -> str:
    field = value.get(key)
    if not isinstance(field, str) or (key != "message" and not field):
        raise ValueError(f"{context} {key} must be a string")
    return field


def sonar_findings(report: Any) -> list[tuple[Any, ...]]:
    findings = []
    for index, issue in enumerate(validate_oracle_report(report)):
        context = f"oracle issue {index}"
        if not isinstance(issue, dict):
            raise ValueError(f"{context} must be an object")
        findings.append(
            _finding(
                rule=_required_string(issue, "rule", context),
                file=_required_string(issue, "file", context),
                message=_required_string(issue, "message", context),
                range_value=issue.get("range"),
                context=context,
                allow_absent_range=True,
            )
        )
    return findings


def hoonarqube_findings(report: Any) -> list[tuple[Any, ...]]:
    if not isinstance(report, dict) or not isinstance(report.get("files"), list):
        raise ValueError("hoonarqube report must contain a files list")
    findings: list[tuple[Any, ...]] = []
    for file_index, file_report in enumerate(report["files"]):
        file_context = f"hoonarqube file report {file_index}"
        if not isinstance(file_report, dict):
            raise ValueError(f"{file_context} must be an object")
        path = _required_string(file_report, "path", file_context)
        file_name = path.replace("\\", "/").rsplit("/", 1)[-1]
        issues = file_report.get("issues")
        if not isinstance(issues, list):
            raise ValueError(f"{file_context} issues must be a list")
        for issue_index, issue in enumerate(issues):
            context = f"{file_context} issue {issue_index}"
            if not isinstance(issue, dict):
                raise ValueError(f"{context} must be an object")
            findings.append(
                _finding(
                    rule=_required_string(issue, "rule_key", context),
                    file=file_name,
                    message=_required_string(issue, "message", context),
                    range_value=issue.get("range"),
                    context=context,
                    allow_absent_range=False,
                )
            )
    return findings


def _for_file_rule(
    findings: Iterable[tuple[Any, ...]], file_name: str, rule: str
) -> Counter[tuple[Any, ...]]:
    return Counter(
        finding
        for finding in findings
        if finding[0] == rule and finding[1] == file_name
    )


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


@dataclass(frozen=True)
class _ComparisonContext:
    sonar: list[tuple[Any, ...]]
    ours: list[tuple[Any, ...]]
    infra: set[str]
    catalog: set[str] | None
    files: set[str] | None
    enterprise_unverified: set[str]


@dataclass(frozen=True)
class _Expectation:
    key: str
    bad: str
    good: str
    minimum: int
    upstream_unverified: str | None


@dataclass(frozen=True)
class _FindingCounters:
    sonar_bad: Counter[tuple[Any, ...]]
    ours_bad: Counter[tuple[Any, ...]]
    sonar_good: Counter[tuple[Any, ...]]
    ours_good: Counter[tuple[Any, ...]]


def _terminal_row(key: Any, status: str, reason: Any) -> dict[str, Any]:
    return {"key": key, "status": status, "reason": str(reason)}


def _validate_key(
    raw: dict[str, Any], seen: set[str], context: _ComparisonContext
) -> tuple[str | None, dict[str, Any] | None]:
    key = raw.get("key")
    if not isinstance(key, str) or not key:
        return None, _terminal_row(key, "INVALID_EXPECTATION", "missing key")
    if key in seen:
        return None, _terminal_row(key, "INVALID_EXPECTATION", "duplicate key")
    seen.add(key)
    if context.catalog is not None and key not in context.catalog:
        return None, _terminal_row(
            key,
            "INVALID_EXPECTATION",
            "expectation key is absent from frozen catalog",
        )
    if key in context.infra or raw.get("infra"):
        reason = raw.get("infra", "upstream analysis infrastructure required")
        return None, _terminal_row(key, "INFRA", reason)
    if raw.get("skip"):
        return None, _terminal_row(key, "SKIPPED", raw["skip"])
    return key, None


def _validate_fixtures(
    raw: dict[str, Any], key: str, available: set[str] | None
) -> tuple[tuple[str, str] | None, dict[str, Any] | None]:
    bad = raw.get("bad")
    if not isinstance(bad, str) or not bad:
        return None, _terminal_row(key, "INVALID_EXPECTATION", "missing bad file")
    good = raw.get("good")
    if good is None:
        good = bad.replace("_bad", "_good")
    if not isinstance(good, str) or not good or good == bad:
        return None, _terminal_row(key, "INVALID_EXPECTATION", "missing good file")
    if available is not None and bad not in available:
        return None, _terminal_row(
            key, "INVALID_EXPECTATION", f"bad fixture does not exist: {bad}"
        )
    if available is not None and good not in available:
        return None, _terminal_row(
            key, "INVALID_EXPECTATION", f"good fixture does not exist: {good}"
        )
    return (bad, good), None


def _validate_minimum(
    raw: dict[str, Any], key: str
) -> tuple[int | None, dict[str, Any] | None]:
    minimum = raw.get("expect_lines_min", 1)
    if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 1:
        return None, _terminal_row(key, "INVALID_EXPECTATION", "invalid minimum")
    return minimum, None


def _validate_upstream_reason(
    raw: dict[str, Any], key: str
) -> tuple[str | None, dict[str, Any] | None]:
    reason = raw.get("upstream_unverified")
    if reason is not None and (not isinstance(reason, str) or not reason.strip()):
        return None, _terminal_row(
            key, "INVALID_EXPECTATION", "invalid upstream-unverified reason"
        )
    return reason, None


def _validate_expectation(
    raw: dict[str, Any], seen: set[str], context: _ComparisonContext
) -> tuple[_Expectation | None, dict[str, Any] | None]:
    key, terminal = _validate_key(raw, seen, context)
    if terminal is not None:
        return None, terminal
    assert key is not None
    fixtures, terminal = _validate_fixtures(raw, key, context.files)
    if terminal is not None:
        return None, terminal
    minimum, terminal = _validate_minimum(raw, key)
    if terminal is not None:
        return None, terminal
    upstream_reason, terminal = _validate_upstream_reason(raw, key)
    if terminal is not None:
        return None, terminal
    assert fixtures is not None and minimum is not None
    bad, good = fixtures
    return _Expectation(key, bad, good, minimum, upstream_reason), None


def _finding_counters(
    expectation: _Expectation, context: _ComparisonContext
) -> _FindingCounters:
    return _FindingCounters(
        sonar_bad=_for_file_rule(context.sonar, expectation.bad, expectation.key),
        ours_bad=_for_file_rule(context.ours, expectation.bad, expectation.key),
        sonar_good=_for_file_rule(context.sonar, expectation.good, expectation.key),
        ours_good=_for_file_rule(context.ours, expectation.good, expectation.key),
    )


def _unverified_status(counters: _FindingCounters, minimum: int, success: str) -> str:
    if counters.ours_good:
        return "GOOD_FIRE"
    if sum(counters.ours_bad.values()) < minimum:
        return "OURS_MISS"
    return success


def _standard_status(counters: _FindingCounters, minimum: int) -> str:
    sonar_missed = sum(counters.sonar_bad.values()) < minimum
    ours_missed = sum(counters.ours_bad.values()) < minimum
    if counters.sonar_good or counters.ours_good:
        return "GOOD_FIRE"
    if sonar_missed and ours_missed:
        return "BOTH_MISS"
    if sonar_missed:
        return "SQ_MISS"
    if ours_missed:
        return "OURS_MISS"
    if counters.sonar_bad != counters.ours_bad:
        return "BAD_MISMATCH"
    return "PASS"


def _comparison_status(
    expectation: _Expectation,
    counters: _FindingCounters,
    context: _ComparisonContext,
) -> str:
    if expectation.upstream_unverified:
        return _unverified_status(counters, expectation.minimum, "UPSTREAM_UNVERIFIED")
    if expectation.key in context.enterprise_unverified:
        return _unverified_status(
            counters, expectation.minimum, "ENTERPRISE_UNVERIFIED"
        )
    return _standard_status(counters, expectation.minimum)


def _comparison_row(
    expectation: _Expectation,
    counters: _FindingCounters,
    context: _ComparisonContext,
) -> dict[str, Any]:
    row = {
        "key": expectation.key,
        "status": _comparison_status(expectation, counters, context),
        "bad": expectation.bad,
        "good": expectation.good,
        "sonar_bad": _serializable(counters.sonar_bad),
        "ours_bad": _serializable(counters.ours_bad),
        "sonar_good": _serializable(counters.sonar_good),
        "ours_good": _serializable(counters.ours_good),
    }
    if expectation.upstream_unverified:
        row["reason"] = expectation.upstream_unverified
    return row


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
    if not isinstance(expected, list):
        raise ValueError("oracle expectations must be a list")
    catalog = _unique_set(catalog_keys, "catalog key")
    files = _unique_set(available_files, "available fixture")
    context = _ComparisonContext(
        sonar=sonar_findings(sonar_report),
        ours=hoonarqube_findings(hoonarqube_report),
        infra=set(infra),
        catalog=catalog,
        files=files,
        enterprise_unverified=set(enterprise_unverified),
    )
    seen: set[str] = set()
    rows: list[dict[str, Any]] = []

    for raw in expected:
        if not isinstance(raw, dict):
            rows.append(
                _terminal_row(
                    None, "INVALID_EXPECTATION", "expectation must be an object"
                )
            )
            continue
        expectation, terminal = _validate_expectation(raw, seen, context)
        if terminal is not None:
            rows.append(terminal)
            continue
        assert expectation is not None
        counters = _finding_counters(expectation, context)
        rows.append(_comparison_row(expectation, counters, context))
    if context.catalog is not None:
        rows.extend(
            _terminal_row(
                key,
                "INVALID_EXPECTATION",
                "catalog key has no oracle expectation",
            )
            for key in sorted(context.catalog - seen)
        )
    return rows


def _unique_set(values: Iterable[str] | None, label: str) -> set[str] | None:
    if values is None:
        return None
    entries = list(values)
    if any(not isinstance(entry, str) or not entry for entry in entries):
        raise ValueError(f"{label} must be a non-empty string")
    unique = set(entries)
    if len(unique) != len(entries):
        raise ValueError(f"duplicate {label}")
    return unique


def counts(rows: Iterable[dict[str, Any]]) -> dict[str, int]:
    return dict(
        sorted(Counter(str(row.get("status", "UNKNOWN")) for row in rows).items())
    )


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
