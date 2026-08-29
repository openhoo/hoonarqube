"""Pure, strict SonarQube oracle comparison primitives.

The comparator deliberately treats parity as equality, not "both analyzers found
something somewhere in the file".  One finding is identified by its rule, file,
message, and complete primary range.  Any missing, extra, or differently located
finding is a divergence.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any, Callable, Iterable, Mapping


ORACLE_REPORT_SCHEMA = 2
NON_FAILURE_STATUSES = frozenset(
    {"PASS", "ENTERPRISE_UNVERIFIED", "UPSTREAM_UNVERIFIED"}
)


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant {value}")


def _reject_duplicate_object_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key {key!r}")
        value[key] = item
    return value


def parse_json(text: str, *, context: str = "JSON") -> Any:
    """Parse standards-compliant JSON with contextual errors."""
    if not isinstance(text, str):
        raise ValueError(f"{context} must be text")
    try:
        return json.loads(
            text,
            parse_constant=_reject_json_constant,
            object_pairs_hook=_reject_duplicate_object_keys,
        )
    except (json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"invalid {context}: {error}") from error


def read_json(path: str | os.PathLike[str]) -> Any:
    """Read strict JSON with a path-bearing error message."""
    source = Path(path)
    try:
        return parse_json(source.read_text(), context=f"JSON in {source}")
    except (OSError, UnicodeError, ValueError) as error:
        raise ValueError(f"invalid JSON in {source}: {error}") from error


def read_jsonl(path: str | os.PathLike[str]) -> list[Any]:
    """Read strict JSON Lines without silently losing malformed records."""
    source = Path(path)
    try:
        lines = source.read_text().splitlines()
    except (OSError, UnicodeError) as error:
        raise ValueError(f"cannot read JSONL {source}: {error}") from error
    rows = []
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            rows.append(
                json.loads(
                    line,
                    parse_constant=_reject_json_constant,
                    object_pairs_hook=_reject_duplicate_object_keys,
                )
            )
        except (json.JSONDecodeError, ValueError) as error:
            raise ValueError(
                f"invalid JSONL in {source} at line {line_number}: {error}"
            ) from error
    return rows


def read_secret_file(path: str | os.PathLike[str]) -> str:
    """Read a caller-owned regular secret file with no group/other access."""
    source = Path(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(source, flags)
    except OSError as error:
        raise RuntimeError(
            f"cannot securely open secret file {source}: {error}"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"secret file must be regular: {source}")
        if os.name == "posix":
            if metadata.st_uid != os.geteuid():
                raise RuntimeError(
                    f"secret file must be owned by current user: {source}"
                )
            if stat.S_IMODE(metadata.st_mode) & 0o077:
                raise RuntimeError(
                    f"secret file permissions must not grant group/other access: {source}"
                )
        with os.fdopen(descriptor, encoding="utf-8") as handle:
            descriptor = -1
            return handle.read()
    except (OSError, UnicodeError) as error:
        raise RuntimeError(
            f"cannot securely read secret file {source}: {error}"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def load_infra_boundaries(path: str | os.PathLike[str]) -> dict[str, str]:
    """Load exact, centrally approved oracle infrastructure exceptions."""
    manifest = read_json(path)
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version",
        "boundaries",
    }:
        raise ValueError("infrastructure boundary manifest has invalid root fields")
    if manifest["schema_version"] != 1:
        raise ValueError("infrastructure boundary manifest schema_version must be 1")
    boundaries = manifest["boundaries"]
    if not isinstance(boundaries, dict) or not boundaries:
        raise ValueError("infrastructure boundary manifest must contain boundaries")
    reasons: dict[str, str] = {}
    for key, boundary in boundaries.items():
        if not isinstance(key, str) or not key:
            raise ValueError("infrastructure boundary key must be a non-empty string")
        if not isinstance(boundary, dict) or set(boundary) != {
            "reason",
            "implementation_gap",
        }:
            raise ValueError(f"infrastructure boundary {key} has invalid fields")
        reason = boundary["reason"]
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError(f"infrastructure boundary {key} has invalid reason")
        if not isinstance(boundary["implementation_gap"], bool):
            raise ValueError(
                f"infrastructure boundary {key} implementation_gap must be boolean"
            )
        reasons[key] = reason
    return reasons


def input_paths_sha256(
    repository: str | os.PathLike[str], roots: Iterable[str | os.PathLike[str]]
) -> str:
    """Hash path identities and contents for repository-contained inputs."""
    repo = Path(repository).resolve()
    paths: list[Path] = []
    for raw_root in roots:
        source_root = Path(raw_root)
        if source_root.is_symlink():
            raise ValueError(f"oracle input must not be a symlink: {source_root}")
        root = source_root.resolve()
        if root.is_dir():
            for path in root.rglob("*"):
                if path.is_symlink():
                    raise ValueError(f"oracle input must not be a symlink: {path}")
                if path.is_file():
                    paths.append(path)
        elif root.is_file():
            paths.append(root)
        else:
            raise ValueError(f"oracle input does not exist: {root}")
    digest = hashlib.sha256()
    for path in sorted(set(paths), key=lambda item: item.as_posix()):
        try:
            relative = path.relative_to(repo).as_posix().encode()
        except ValueError as error:
            raise ValueError(f"oracle input is outside repository: {path}") from error
        data = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def write_json_atomic(
    path: str | os.PathLike[str], value: Any, *, indent: int | None = None
) -> None:
    """Replace a JSON artifact atomically after full serialization and fsync."""
    rendered = json.dumps(value, indent=indent, allow_nan=False) + "\n"
    write_text_atomic(path, rendered)


def write_text_atomic(path: str | os.PathLike[str], text: str) -> None:
    """Replace a UTF-8 text artifact atomically after a durable temporary write."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, destination)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


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


def _sonar_component_file(
    issue: dict[str, Any], context: str, expected_project: str | None
) -> str:
    component = issue.get("component")
    if isinstance(component, dict):
        component = component.get("path")
    if not isinstance(component, str) or not component:
        raise ValueError(f"{context} component must identify a file")
    normalized = component.replace("\\", "/")
    if expected_project is not None:
        prefix = f"{expected_project}:"
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :]
        elif normalized == expected_project:
            normalized = ""
    file_name = normalized.rsplit("/", 1)[-1]
    if file_name in {"", ".", ".."}:
        raise ValueError(f"{context} component must identify a file")
    return file_name


def canonical_sonar_issue(
    issue: Any, *, hotspot: bool, expected_project: str | None = None
) -> dict[str, Any]:
    """Normalize one API issue while rejecting incomplete identity and ranges."""
    context = "Sonar hotspot" if hotspot else "Sonar issue"
    if not isinstance(issue, dict):
        raise ValueError(f"{context} must be an object")
    rule_field = "ruleKey" if hotspot else "rule"
    rule = _required_string(issue, rule_field, context)
    message = _required_string(issue, "message", context)
    file_name = _sonar_component_file(issue, context, expected_project)

    text_range = issue.get("textRange")
    if text_range is None:
        if issue.get("line") is not None:
            raise ValueError(f"{context} line-only range is not exact evidence")
        range_value = None
    else:
        if not isinstance(text_range, dict):
            raise ValueError(f"{context} textRange must be an object")
        start_line = text_range.get("startLine")
        range_value = {
            "start": {
                "line": start_line,
                "column": text_range.get("startOffset"),
            },
            "end": {
                "line": text_range.get("endLine", start_line),
                "column": text_range.get("endOffset"),
            },
        }
        _canonical_range(range_value, context=context, allow_absent=False)
    return {
        "rule": rule,
        "file": file_name,
        "message": message,
        "range": range_value,
        "hotspot": hotspot,
    }


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
    seen_paths: set[str] = set()
    basename_paths: dict[str, str] = {}
    for file_index, file_report in enumerate(report["files"]):
        file_context = f"hoonarqube file report {file_index}"
        if not isinstance(file_report, dict):
            raise ValueError(f"{file_context} must be an object")
        path = _required_string(file_report, "path", file_context)
        normalized_path = path.replace("\\", "/")
        file_name = normalized_path.rsplit("/", 1)[-1]
        if file_name in {"", ".", ".."}:
            raise ValueError(f"{file_context} path must identify a file")
        if normalized_path in seen_paths:
            raise ValueError(f"duplicate hoonarqube file report path: {path}")
        seen_paths.add(normalized_path)
        previous_path = basename_paths.setdefault(file_name, normalized_path)
        if previous_path != normalized_path:
            raise ValueError(
                f"hoonarqube file basename collision for {file_name}: "
                f"{previous_path} and {normalized_path}"
            )
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


def _serializable(
    counter: Counter[tuple[Any, ...]], *, include_file: bool = False
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for finding, count in sorted(counter.items(), key=repr):
        _, _, message, start_line, start_column, end_line, end_column = finding
        row = {
            "message": message,
            "range": {
                "start": {"line": start_line, "column": start_column},
                "end": {"line": end_line, "column": end_column},
            },
            "count": count,
        }
        if include_file:
            row["file"] = finding[1]
        rows.append(row)
    return rows


@dataclass(frozen=True)
class _ComparisonContext:
    sonar: list[tuple[Any, ...]]
    ours: list[tuple[Any, ...]]
    infra: dict[str, str]
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
    sonar_other: Counter[tuple[Any, ...]]
    ours_other: Counter[tuple[Any, ...]]

    @property
    def sonar_all(self) -> Counter[tuple[Any, ...]]:
        return self.sonar_bad + self.sonar_good + self.sonar_other

    @property
    def ours_all(self) -> Counter[tuple[Any, ...]]:
        return self.ours_bad + self.ours_good + self.ours_other


def _terminal_row(key: Any, status: str, reason: Any) -> dict[str, Any]:
    return {"key": key, "status": status, "reason": str(reason)}


def _validate_infra(
    key: str, declared: Any, approved: dict[str, str]
) -> dict[str, Any]:
    if not isinstance(declared, str) or not declared.strip():
        return _terminal_row(
            key, "INVALID_EXPECTATION", "invalid infrastructure reason"
        )
    approved_reason = approved.get(key)
    if approved_reason is None:
        return _terminal_row(
            key, "INVALID_EXPECTATION", "unapproved infrastructure boundary"
        )
    if declared != approved_reason:
        return _terminal_row(
            key,
            "INVALID_EXPECTATION",
            "infrastructure reason does not match approved boundary",
        )
    return _terminal_row(key, "INFRA", approved_reason)


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
    declared_infra = raw.get("infra")
    if declared_infra is not None:
        return None, _validate_infra(key, declared_infra, context.infra)
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
    def for_other(findings: Iterable[tuple[Any, ...]]) -> Counter[tuple[Any, ...]]:
        return Counter(
            finding
            for finding in findings
            if finding[0] == expectation.key
            and finding[1] not in {expectation.bad, expectation.good}
        )

    return _FindingCounters(
        sonar_bad=_for_file_rule(context.sonar, expectation.bad, expectation.key),
        ours_bad=_for_file_rule(context.ours, expectation.bad, expectation.key),
        sonar_good=_for_file_rule(context.sonar, expectation.good, expectation.key),
        ours_good=_for_file_rule(context.ours, expectation.good, expectation.key),
        sonar_other=for_other(context.sonar),
        ours_other=for_other(context.ours),
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
    if counters.sonar_all != counters.ours_all:
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
        "sonar_other": _serializable(counters.sonar_other, include_file=True),
        "ours_other": _serializable(counters.ours_other, include_file=True),
    }
    if expectation.upstream_unverified:
        row["reason"] = expectation.upstream_unverified
    return row


def compare_reports(
    expected: list[dict[str, Any]],
    sonar_report: Any,
    hoonarqube_report: Any,
    infra: Mapping[str, str] | None = None,
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
        infra=dict(infra or {}),
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
    if context.catalog is not None:
        rows.extend(_unexpected_finding_rows(context, context.catalog))
    return rows


def _unexpected_finding_rows(
    context: _ComparisonContext, declared_rules: set[str]
) -> list[dict[str, Any]]:
    unexpected: set[tuple[str, str, str]] = set()
    for source, findings in (("Sonar", context.sonar), ("hoonarqube", context.ours)):
        for finding in findings:
            rule, file_name = finding[:2]
            if rule not in declared_rules:
                unexpected.add((str(rule), source, "rule absent from oracle contract"))
            elif context.files is not None and file_name not in context.files:
                unexpected.add(
                    (
                        str(rule),
                        source,
                        f"finding references unknown fixture {file_name}",
                    )
                )
    return [
        _terminal_row(key, "INVALID_ARTIFACT", f"{source}: {reason}")
        for key, source, reason in sorted(unexpected)
    ]


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


def parse_report_task(
    text: str, *, expected_project: str | None = None
) -> dict[str, str]:
    if not isinstance(text, str):
        raise ValueError("report-task.txt must be text")
    task: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        if "=" not in line:
            raise ValueError(f"report-task.txt line {line_number} lacks '='")
        key, value = line.split("=", 1)
        if not key or not value:
            raise ValueError(f"report-task.txt line {line_number} is incomplete")
        if key in task:
            raise ValueError(f"report-task.txt contains duplicate {key}")
        task[key] = value
    if not task.get("ceTaskId"):
        raise ValueError("report-task.txt lacks ceTaskId")
    if expected_project is not None and task.get("projectKey") != expected_project:
        raise ValueError(
            f"report-task.txt projectKey must be {expected_project!r}; "
            f"got {task.get('projectKey')!r}"
        )
    return task


def wait_for_compute_engine(
    task_id: str,
    fetch_status: Callable[[str], str | None],
    pause: Callable[[], None],
    attempts: int = 120,
) -> str:
    """Wait until SonarQube Compute Engine commits the submitted analysis."""
    if not isinstance(task_id, str) or not task_id:
        raise ValueError("compute engine task ID must be a non-empty string")
    if not isinstance(attempts, int) or isinstance(attempts, bool) or attempts < 1:
        raise ValueError("compute engine attempts must be a positive integer")
    for _ in range(attempts):
        status = fetch_status(task_id)
        if status in {"SUCCESS", "FAILED", "CANCELED"}:
            return status
        if status not in {"PENDING", "IN_PROGRESS"}:
            raise ValueError(f"invalid compute engine status: {status!r}")
        pause()
    return "TIMEOUT"
