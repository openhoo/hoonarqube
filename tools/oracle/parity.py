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
import posixpath
import stat
import tempfile
from typing import Any, Callable, Iterable, Mapping


ORACLE_REPORT_SCHEMA = 2
SECURITY_EVIDENCE_SCHEMA = 1
NON_FAILURE_STATUSES = frozenset(
    {"PASS", "ENTERPRISE_UNVERIFIED", "UPSTREAM_UNVERIFIED"}
)

# Security detector metadata is deliberately compared outside the legacy
# finding tuple.  The latter remains the stable issue-only contract used by
# all existing reports.
_SECURITY_REVIEW_FIELDS = ("status", "resolution", "assignee")


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
    seen_keys: set[str] | None = None,
) -> tuple[list[Any], int, int, bool]:
    """Validate paging and unique item keys; extend caller's keys only on success."""
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
    page_keys = _validate_search_item_keys(items, seen_keys, context)
    if seen_keys is not None:
        seen_keys.update(page_keys)
    return items, total, page_size, offset + len(items) == total


def _validate_search_item_keys(
    items: list[dict[str, Any]], seen_keys: set[str] | None, context: str
) -> set[str]:
    page_keys: set[str] = set()
    for index, item in enumerate(items):
        key = _required_string(item, "key", f"{context} item {index}")
        if key in page_keys or (seen_keys is not None and key in seen_keys):
            raise ValueError(f"{context} contains a duplicate item key")
        page_keys.add(key)
    return page_keys


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


def _canonical_project_path(
    value: Any, *, context: str, expected_project: str | None = None
) -> str:
    """Return a normalized project-relative path without basename collisions."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{context} path must be a non-empty string")
    normalized = value.replace("\\", "/")
    if expected_project is not None:
        prefix = f"{expected_project}:"
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :]
        elif normalized == expected_project:
            normalized = ""
    if normalized.startswith("/"):
        raise ValueError(f"{context} path must be project-relative")
    normalized = posixpath.normpath(normalized)
    if normalized in {"", ".", ".."} or normalized.startswith("../"):
        raise ValueError(f"{context} path must identify a project file")
    return normalized


def _sonar_component_path(
    issue: dict[str, Any], context: str, expected_project: str | None
) -> str:
    component = issue.get("component")
    if isinstance(component, dict):
        component = component.get("path")
    return _canonical_project_path(
        component, context=f"{context} component", expected_project=expected_project
    )


def _range_object(
    canonical: tuple[int | None, int | None, int | None, int | None],
) -> dict[str, dict[str, int]] | None:
    if all(coordinate is None for coordinate in canonical):
        return None
    start_line, start_column, end_line, end_column = canonical
    assert (
        start_line is not None
        and start_column is not None
        and end_line is not None
        and end_column is not None
    )
    return {
        "start": {"line": start_line, "column": start_column},
        "end": {"line": end_line, "column": end_column},
    }


def _security_api_range(
    value: dict[str, Any], *, context: str
) -> dict[str, dict[str, int]] | None:
    if "range" in value:
        raw_range = value["range"]
    elif "textRange" in value:
        text_range = value["textRange"]
        if text_range is None:
            raw_range = None
        elif isinstance(text_range, dict):
            start_line = text_range.get("startLine")
            raw_range = {
                "start": {
                    "line": start_line,
                    "column": text_range.get("startOffset"),
                },
                "end": {
                    "line": text_range.get("endLine", start_line),
                    "column": text_range.get("endOffset"),
                },
            }
        else:
            raise ValueError(f"{context} textRange must be an object or null")
    else:
        raise ValueError(f"{context} range/textRange field is missing")
    canonical = _canonical_range(raw_range, context=context, allow_absent=True)
    return _range_object(canonical)


def _security_location(
    value: Any,
    *,
    context: str,
    expected_project: str | None = None,
    primary_file: str | None = None,
) -> dict[str, Any]:
    """Normalize one immutable flow/secondary location."""
    if not isinstance(value, dict):
        raise ValueError(f"{context} must be an object")
    if "file" in value:
        file_name = _canonical_project_path(
            value["file"], context=f"{context} file", expected_project=expected_project
        )
        message = value.get("message")
    elif "path" in value and "component" not in value:
        raw_path = value.get("path")
        file_name = (
            primary_file
            if raw_path is None and primary_file is not None
            else _canonical_project_path(
                raw_path, context=f"{context} path", expected_project=expected_project
            )
        )
        message = value.get("message")
    elif "component" in value:
        file_name = _sonar_component_path(value, context, expected_project)
        message = value.get("msg", value.get("message"))
    else:
        raise ValueError(f"{context} must identify a file")
    if not isinstance(message, str):
        raise ValueError(f"{context} message must be a string")
    return {
        "file": file_name,
        "message": message,
        "range": _security_api_range(value, context=context),
    }


def _security_locations(
    raw: Any,
    *,
    context: str,
    expected_project: str | None = None,
    primary_file: str | None = None,
) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise ValueError(f"{context} must be a list")
    return [
        _security_location(
            location,
            context=f"{context} {index}",
            expected_project=expected_project,
            primary_file=primary_file,
        )
        for index, location in enumerate(raw)
    ]


def _security_flow_locations_messages_unavailable(
    flow: Any, *, flow_index: int, expected_project: str | None
) -> bool:
    locations = flow.get("locations") if isinstance(flow, dict) else flow
    if not isinstance(locations, list) or not locations:
        return False
    for location_index, location in enumerate(locations):
        if (
            not isinstance(location, dict)
            or "component" not in location
            or "msg" in location
            or "message" in location
            or not isinstance(location.get("msgFormattings"), list)
        ):
            return False
        try:
            _canonical_project_path(
                location["component"],
                context=f"security flow {flow_index} location {location_index} component",
                expected_project=expected_project,
            )
            _security_api_range(
                location,
                context=f"security flow {flow_index} location {location_index}",
            )
        except ValueError:
            return False
    return True


def _security_flow_messages_unavailable(
    raw_flows: Any, *, expected_project: str | None = None
) -> bool:
    """Recognize Sonar's flow shape without per-location messages."""
    return (
        isinstance(raw_flows, list)
        and bool(raw_flows)
        and all(
            _security_flow_locations_messages_unavailable(
                flow,
                flow_index=flow_index,
                expected_project=expected_project,
            )
            for flow_index, flow in enumerate(raw_flows)
        )
    )


def _security_flows(
    issue: dict[str, Any],
    *,
    context: str,
    expected_project: str | None,
    primary_file: str,
) -> list[list[dict[str, Any]]]:
    if "flows" not in issue:
        raise ValueError(f"{context} flows field is missing")
    raw_flows = issue["flows"]
    if not isinstance(raw_flows, list):
        raise ValueError(f"{context} flows must be a list")
    flows: list[list[dict[str, Any]]] = []
    for flow_index, flow in enumerate(raw_flows):
        locations = flow.get("locations") if isinstance(flow, dict) else flow
        if not isinstance(locations, list) or not locations:
            raise ValueError(f"{context} flow {flow_index} must contain locations")
        flows.append(
            _security_locations(
                locations,
                context=f"{context} flow {flow_index}",
                expected_project=expected_project,
                primary_file=primary_file,
            )
        )
    return flows


def _security_review(issue: dict[str, Any], *, context: str) -> dict[str, Any]:
    review: dict[str, Any] = {}
    for key in _SECURITY_REVIEW_FIELDS:
        value = issue.get(key)
        if value is not None and not isinstance(value, str):
            raise ValueError(f"{context} review {key} must be a string or null")
        review[key] = value
    review["available"] = any(key in issue for key in _SECURITY_REVIEW_FIELDS)
    return review


def canonical_sonar_security_issue(
    issue: Any, *, hotspot: bool, expected_project: str | None = None
) -> dict[str, Any]:
    """Normalize complete detector and review evidence from a Sonar API issue."""
    context = "Sonar hotspot" if hotspot else "Sonar security issue"
    if not isinstance(issue, dict):
        raise ValueError(f"{context} must be an object")
    try:
        primary = canonical_sonar_issue(
            issue, hotspot=hotspot, expected_project=expected_project
        )
        primary_range_available = primary["range"] is not None
    except ValueError as error:
        if not (hotspot and "line-only range" in str(error)):
            raise
        # Hotspot search can expose only a line. Keep the finding visible, but
        # explicitly mark the immutable primary range as unavailable.
        primary_range_available = False
        primary = {
            "rule": _required_string(issue, "ruleKey", context),
            "file": _sonar_component_file(issue, context, expected_project),
            "message": _required_string(issue, "message", context),
            "range": None,
        }
    if hotspot:
        detector_kind = "SECURITY_HOTSPOT"
    else:
        detector_kind = _required_string(issue, "type", context)
    primary_path = _sonar_component_path(issue, context, expected_project)
    if "flows" not in issue:
        if not hotspot:
            raise ValueError(f"{context} flows field is missing")
        flows: list[list[dict[str, Any]]] = []
        flow_available = False
    else:
        try:
            flows = _security_flows(
                issue,
                context=context,
                expected_project=expected_project,
                primary_file=primary_path,
            )
        except ValueError:
            if not _security_flow_messages_unavailable(
                issue.get("flows"), expected_project=expected_project
            ):
                raise
            flows = []
            flow_available = False
        else:
            flow_available = True
    secondary_available = "secondaryLocations" in issue
    secondary = _security_locations(
        issue.get("secondaryLocations", []),
        context=f"{context} secondaryLocations",
        expected_project=expected_project,
        primary_file=primary_path,
    )
    return {
        "rule": primary["rule"],
        "file": primary_path,
        "message": primary["message"],
        "range": primary["range"],
        "detector": {
            "kind": detector_kind,
            "flows": flows,
            "secondary_locations": secondary,
            "flow_evidence_available": flow_available,
            "secondary_location_evidence_available": secondary_available,
            "primary_range_evidence_available": primary_range_available,
        },
        "review": _security_review(issue, context=context),
    }


def _canonical_security_review(value: Any, *, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{context} review must be an object")
    missing_review = sorted(set(_SECURITY_REVIEW_FIELDS) - set(value))
    if missing_review:
        raise ValueError(
            f"{context} review missing fields: {', '.join(missing_review)}"
        )
    normalized: dict[str, Any] = {}
    for key in _SECURITY_REVIEW_FIELDS:
        review_value = value[key]
        if review_value is not None and not isinstance(review_value, str):
            raise ValueError(f"{context} review {key} must be a string or null")
        normalized[key] = review_value
    if "available" in value and not isinstance(value["available"], bool):
        raise ValueError(f"{context} review available must be boolean")
    normalized["available"] = bool(
        value.get(
            "available",
            any(value[key] is not None for key in _SECURITY_REVIEW_FIELDS),
        )
    )
    return normalized


def _canonical_security_detector(
    value: Any,
    *,
    context: str,
    expected_project: str | None,
    file_name: str,
    canonical_range: tuple[int | None, int | None, int | None, int | None],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{context} detector must be an object")
    detector_required = {
        "flows",
        "secondary_locations",
        "flow_evidence_available",
        "secondary_location_evidence_available",
        "primary_range_evidence_available",
    }
    detector_missing = sorted(detector_required - set(value))
    if detector_missing:
        raise ValueError(
            f"{context} detector missing fields: {', '.join(detector_missing)}"
        )
    detector_context = f"{context} detector"
    kind = _required_string(value, "kind", detector_context)
    availability_keys = (
        "flow_evidence_available",
        "secondary_location_evidence_available",
        "primary_range_evidence_available",
    )
    for availability_key in availability_keys:
        if not isinstance(value[availability_key], bool):
            raise ValueError(f"{context} detector {availability_key} must be boolean")
    flows = _security_flows(
        value,
        context=detector_context,
        expected_project=expected_project,
        primary_file=file_name,
    )
    secondary = _security_locations(
        value["secondary_locations"],
        context=f"{detector_context} secondary_locations",
        expected_project=expected_project,
        primary_file=file_name,
    )
    if value["primary_range_evidence_available"] != (canonical_range != (None,) * 4):
        raise ValueError(f"{context} primary range availability does not match range")
    if not value["flow_evidence_available"] and flows:
        raise ValueError(f"{context} flow evidence unavailable but flows are populated")
    if not value["secondary_location_evidence_available"] and secondary:
        raise ValueError(
            f"{context} secondary location evidence unavailable but locations are populated"
        )
    return {
        "kind": kind,
        "flows": flows,
        "secondary_locations": secondary,
        "flow_evidence_available": value["flow_evidence_available"],
        "secondary_location_evidence_available": value[
            "secondary_location_evidence_available"
        ],
        "primary_range_evidence_available": value["primary_range_evidence_available"],
    }


def _canonical_security_finding(
    value: Any, *, context: str, expected_project: str | None
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{context} must be an object")
    required = {"rule", "file", "message", "range", "detector", "review"}
    missing = sorted(required - set(value))
    if missing:
        raise ValueError(f"{context} missing fields: {', '.join(missing)}")
    rule = _required_string(value, "rule", context)
    file_name = _canonical_project_path(
        value["file"], context=f"{context} file", expected_project=expected_project
    )
    message = _required_string(value, "message", context)
    canonical_range = _canonical_range(
        value["range"], context=context, allow_absent=True
    )
    detector = _canonical_security_detector(
        value["detector"],
        context=context,
        expected_project=expected_project,
        file_name=file_name,
        canonical_range=canonical_range,
    )
    return {
        "rule": rule,
        "file": file_name,
        "message": message,
        "range": _range_object(canonical_range),
        "detector": detector,
        "review": _canonical_security_review(value["review"], context=context),
    }


def _validate_security_project(
    report: dict[str, Any], expected_project: str | None
) -> str:
    project = report["project"]
    if not isinstance(project, str) or not project.strip():
        raise ValueError("security evidence project must be a non-empty string")
    if expected_project is not None and project != expected_project:
        raise ValueError(
            f"security evidence project must be {expected_project!r}, got {project!r}"
        )
    return project


def _validate_security_metadata(report: dict[str, Any]) -> None:
    for key in ("source", "edition"):
        if not isinstance(report[key], str) or not report[key].strip():
            raise ValueError(f"security evidence {key} must be a non-empty string")
    for key in ("sensor", "execution"):
        if key in report and not isinstance(report[key], dict):
            raise ValueError(f"security evidence {key} must be an object")


def _validate_security_evidence_root(
    report: Any, expected_project: str | None
) -> tuple[dict[str, Any], str]:
    if not isinstance(report, dict):
        raise ValueError("security evidence must be an object")
    required_root = {
        "schema_version",
        "project",
        "source",
        "edition",
        "findings",
        "limits",
    }
    missing_root = sorted(required_root - set(report))
    if missing_root:
        raise ValueError(
            f"security evidence missing root fields: {', '.join(missing_root)}"
        )
    if report.get("schema_version") != SECURITY_EVIDENCE_SCHEMA:
        raise ValueError(
            f"security evidence schema_version {SECURITY_EVIDENCE_SCHEMA} required"
        )
    project = _validate_security_project(report, expected_project)
    _validate_security_metadata(report)
    return report, project


def _validate_security_limits(limits: Any) -> None:
    if not isinstance(limits, list) or any(
        not isinstance(limit, str) or not limit.strip() for limit in limits
    ):
        raise ValueError("security evidence limits must be a list of strings")


def validate_security_evidence(
    report: Any, *, expected_project: str | None = None
) -> list[dict[str, Any]]:
    """Validate a versioned security artifact without weakening missing fields."""
    validated_report, project = _validate_security_evidence_root(
        report, expected_project
    )
    findings = validated_report["findings"]
    if not isinstance(findings, list):
        raise ValueError("security evidence findings must be a list")
    _validate_security_limits(validated_report["limits"])
    return [
        _canonical_security_finding(
            finding,
            context=f"security finding {index}",
            expected_project=project,
        )
        for index, finding in enumerate(findings)
    ]


def canonical_hoonarqube_security_issue(
    issue: Any,
    *,
    rule_type: str,
    file: str,
    expected_project: str,
) -> dict[str, Any]:
    """Adapt one local IR issue without inventing omitted flow evidence."""
    context = "Hoonarqube security issue"
    if not isinstance(issue, dict):
        raise ValueError(f"{context} must be an object")
    rule = _required_string(issue, "rule_key", context)
    message = _required_string(issue, "message", context)
    if not isinstance(rule_type, str) or not rule_type.strip():
        raise ValueError(f"{context} detector kind must be a non-empty string")
    if "range" not in issue:
        raise ValueError(f"{context} range field is missing")
    range_value = _range_object(
        _canonical_range(issue["range"], context=context, allow_absent=True)
    )
    file_name = _canonical_project_path(
        file, context=f"{context} file", expected_project=expected_project
    )
    # The IR deliberately omits an empty `flows` vector during serde.  This
    # adapter knows that source schema, so it materializes the omission as an
    # explicit validated empty list; arbitrary security artifacts still reject
    # a missing field in `_security_flows`.
    flow_issue = issue if "flows" in issue else {**issue, "flows": []}
    flows = _security_flows(
        flow_issue,
        context=context,
        expected_project=expected_project,
        primary_file=file_name,
    )
    secondary_available = "secondary_locations" in issue
    secondary = _security_locations(
        issue.get("secondary_locations", []),
        context=f"{context} secondary_locations",
        expected_project=expected_project,
        primary_file=file_name,
    )
    return {
        "rule": rule,
        "file": file_name,
        "message": message,
        "range": range_value,
        "detector": {
            "kind": rule_type,
            "flows": flows,
            "secondary_locations": secondary,
            "flow_evidence_available": True,
            "secondary_location_evidence_available": secondary_available,
            "primary_range_evidence_available": range_value is not None,
        },
        "review": {
            "status": None,
            "resolution": None,
            "assignee": None,
            "available": False,
        },
    }


def _canonical_local_security_path(
    raw_path: Any, *, context: str, root: Path | None
) -> str:
    if not isinstance(raw_path, str) or not raw_path:
        raise ValueError(f"{context} path must be a non-empty string")
    if root is None:
        return raw_path
    path = Path(raw_path)
    candidate = path if path.is_absolute() else root / path
    try:
        return candidate.resolve().relative_to(root).as_posix()
    except ValueError as error:
        raise ValueError(f"{context} path is outside project root") from error


def _build_local_security_issue(
    issue: Any,
    *,
    context: str,
    rule_types: Mapping[str, str],
    file: str,
    project: str,
) -> dict[str, Any] | None:
    if not isinstance(issue, dict):
        raise ValueError(f"{context} must be an object")
    rule = issue.get("rule_key")
    if rule not in rule_types:
        return None
    return canonical_hoonarqube_security_issue(
        issue,
        rule_type=rule_types[rule],
        file=file,
        expected_project=project,
    )


def _build_local_security_file(
    file_report: Any,
    *,
    context: str,
    root: Path | None,
    rule_types: Mapping[str, str],
    project: str,
) -> list[dict[str, Any]]:
    if not isinstance(file_report, dict):
        raise ValueError(f"{context} must be an object")
    file_path = _canonical_local_security_path(
        file_report.get("path"), context=context, root=root
    )
    issues = file_report.get("issues")
    if not isinstance(issues, list):
        raise ValueError(f"{context} issues must be a list")
    findings: list[dict[str, Any]] = []
    for issue_index, issue in enumerate(issues):
        finding = _build_local_security_issue(
            issue,
            context=f"{context} issue {issue_index}",
            rule_types=rule_types,
            file=file_path,
            project=project,
        )
        if finding is not None:
            findings.append(finding)
    return findings


def build_hoonarqube_security_evidence(
    report: Any,
    *,
    project: str,
    rule_types: Mapping[str, str],
    project_root: str | os.PathLike[str] | None = None,
    limits: Iterable[str] = (),
) -> dict[str, Any]:
    """Build a strict local security artifact from the existing files report."""
    if not isinstance(project, str) or not project.strip():
        raise ValueError("security evidence project must be a non-empty string")
    if not isinstance(report, dict) or not isinstance(report.get("files"), list):
        raise ValueError("hoonarqube report must contain a files list")
    root = Path(project_root).resolve() if project_root is not None else None
    findings: list[dict[str, Any]] = []
    for file_index, file_report in enumerate(report["files"]):
        findings.extend(
            _build_local_security_file(
                file_report,
                context=f"hoonarqube security file report {file_index}",
                root=root,
                rule_types=rule_types,
                project=project,
            )
        )
    artifact = {
        "schema_version": SECURITY_EVIDENCE_SCHEMA,
        "project": project,
        "source": "hoonarqube",
        "edition": "local",
        "sensor": {"kind": "direct-analyzer"},
        "findings": findings,
        "limits": sorted(
            {limit for limit in limits if isinstance(limit, str) and limit.strip()}
        ),
    }
    validate_security_evidence(artifact, expected_project=project)
    return artifact


def _freeze_security(value: Any) -> Any:
    if isinstance(value, dict):
        return (
            "__dict__",
            tuple((key, _freeze_security(value[key])) for key in sorted(value)),
        )
    if isinstance(value, list):
        return ("__list__", tuple(_freeze_security(item) for item in value))
    return ("__value__", value)


def _thaw_security(value: Any) -> Any:
    if not isinstance(value, tuple) or not value:
        return value
    tag = value[0]
    if tag == "__dict__":
        return {key: _thaw_security(item) for key, item in value[1]}
    if tag == "__list__":
        return [_thaw_security(item) for item in value[1]]
    if tag == "__value__":
        return value[1]
    return value


def _security_detector_key(finding: dict[str, Any]) -> tuple[Any, ...]:
    return (
        finding["rule"],
        finding["file"],
        finding["message"],
        _freeze_security(finding["range"]),
        _freeze_security(finding["detector"]),
    )


def _security_detector_identity(finding: dict[str, Any]) -> tuple[Any, ...]:
    detector = finding["detector"]
    return (
        finding["rule"],
        finding["file"],
        finding["message"],
        detector["kind"],
    )


def _security_detector_compatible(left: dict[str, Any], right: dict[str, Any]) -> bool:
    """Return whether both findings' known detector facts agree."""
    if _security_detector_identity(left) != _security_detector_identity(right):
        return False
    left_detector = left["detector"]
    right_detector = right["detector"]
    return not (
        (
            left_detector["primary_range_evidence_available"]
            and right_detector["primary_range_evidence_available"]
            and left["range"] != right["range"]
        )
        or (
            left_detector["flow_evidence_available"]
            and right_detector["flow_evidence_available"]
            and left_detector["flows"] != right_detector["flows"]
        )
        or (
            left_detector["secondary_location_evidence_available"]
            and right_detector["secondary_location_evidence_available"]
            and left_detector["secondary_locations"]
            != right_detector["secondary_locations"]
        )
    )


_SECURITY_COMPARISON_WORK_BUDGET = 100_000


def _security_detector_mask(finding: dict[str, Any]) -> tuple[bool, bool, bool]:
    detector = finding["detector"]
    return (
        detector["primary_range_evidence_available"],
        detector["flow_evidence_available"],
        detector["secondary_location_evidence_available"],
    )


def _security_projected_detector_key(
    finding: dict[str, Any], mask: tuple[bool, bool, bool]
) -> tuple[Any, ...]:
    detector = finding["detector"]
    return (
        _security_detector_identity(finding),
        _freeze_security(finding["range"]) if mask[0] else None,
        _freeze_security(detector["flows"]) if mask[1] else None,
        _freeze_security(detector["secondary_locations"]) if mask[2] else None,
    )


def _security_unmatched_rows(
    left: list[dict[str, Any]],
    right: list[dict[str, Any]],
    key: Callable[[dict[str, Any]], tuple[Any, ...]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    left_counter = Counter(key(finding) for finding in left)
    right_counter = Counter(key(finding) for finding in right)
    left_rows = {key(finding): finding for finding in left}
    right_rows = {key(finding): finding for finding in right}
    missing: list[dict[str, Any]] = []
    extra: list[dict[str, Any]] = []
    for row_key, count in (left_counter - right_counter).items():
        missing.extend([left_rows[row_key]] * count)
    for row_key, count in (right_counter - left_counter).items():
        extra.extend([right_rows[row_key]] * count)
    return missing, extra


def _security_group_detector_rows(
    sonar: list[dict[str, Any]], ours: list[dict[str, Any]]
) -> dict[
    tuple[Any, ...],
    tuple[list[dict[str, Any]], list[dict[str, Any]]],
]:
    groups: dict[
        tuple[Any, ...],
        tuple[list[dict[str, Any]], list[dict[str, Any]]],
    ] = {}
    for side, findings in (("sonar", sonar), ("ours", ours)):
        for finding in findings:
            group = groups.setdefault(_security_detector_identity(finding), ([], []))
            (group[0] if side == "sonar" else group[1]).append(finding)
    return groups


def _security_uniform_detector_rows(
    sonar_rows: list[dict[str, Any]], ours_rows: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]] | None:
    sonar_masks = {_security_detector_mask(finding) for finding in sonar_rows}
    ours_masks = {_security_detector_mask(finding) for finding in ours_rows}
    if len(sonar_masks) > 1 or len(ours_masks) > 1:
        return None
    sonar_mask = next(iter(sonar_masks))
    ours_mask = next(iter(ours_masks))
    common_mask = (
        sonar_mask[0] and ours_mask[0],
        sonar_mask[1] and ours_mask[1],
        sonar_mask[2] and ours_mask[2],
    )
    return _security_unmatched_rows(
        sonar_rows,
        ours_rows,
        lambda finding, common_mask=common_mask: _security_projected_detector_key(
            finding, common_mask
        ),
    )


def _security_spend_work(remaining_work: int) -> tuple[int, bool]:
    if remaining_work <= 0:
        return remaining_work, False
    return remaining_work - 1, True


def _security_compatibility_graph(
    sonar_rows: list[dict[str, Any]],
    ours_rows: list[dict[str, Any]],
    remaining_work: int,
) -> tuple[list[list[int]], int, bool]:
    compatible: list[list[int]] = []
    for sonar_finding in sonar_rows:
        row: list[int] = []
        for ours_index, ours_finding in enumerate(ours_rows):
            remaining_work, spent = _security_spend_work(remaining_work)
            if not spent:
                return compatible, remaining_work, True
            if _security_detector_compatible(sonar_finding, ours_finding):
                row.append(ours_index)
        compatible.append(row)
    return compatible, remaining_work, False


def _security_find_augmenting_path(
    start: int,
    compatible: list[list[int]],
    ours_owner: list[int | None],
    remaining_work: int,
) -> tuple[dict[int, int], int | None, int, bool]:
    queue = [start]
    queue_index = 0
    visited_sonar = {start}
    visited_ours: set[int] = set()
    parent_ours: dict[int, int] = {}
    free_ours: int | None = None
    exhausted = False
    while queue_index < len(queue) and free_ours is None:
        sonar_index = queue[queue_index]
        queue_index += 1
        for ours_index in compatible[sonar_index]:
            remaining_work, spent = _security_spend_work(remaining_work)
            if not spent:
                exhausted = True
                break
            if ours_index in visited_ours:
                continue
            visited_ours.add(ours_index)
            parent_ours[ours_index] = sonar_index
            previous_sonar = ours_owner[ours_index]
            if previous_sonar is None:
                free_ours = ours_index
                break
            if previous_sonar not in visited_sonar:
                visited_sonar.add(previous_sonar)
                queue.append(previous_sonar)
        if exhausted:
            break
    return parent_ours, free_ours, remaining_work, exhausted


def _security_assign_compatible_rows(
    compatible: list[list[int]],
    sonar_count: int,
    ours_count: int,
    remaining_work: int,
) -> tuple[list[int | None], list[int | None], int, bool]:
    sonar_owner: list[int | None] = [None] * sonar_count
    ours_owner: list[int | None] = [None] * ours_count
    for start in range(sonar_count):
        parent_ours, free_ours, remaining_work, exhausted = (
            _security_find_augmenting_path(
                start,
                compatible,
                ours_owner,
                remaining_work,
            )
        )
        if exhausted:
            return sonar_owner, ours_owner, remaining_work, True
        if free_ours is None:
            continue
        ours_index: int | None = free_ours
        while ours_index is not None:
            sonar_index = parent_ours[ours_index]
            previous_ours = sonar_owner[sonar_index]
            sonar_owner[sonar_index] = ours_index
            ours_owner[ours_index] = sonar_index
            ours_index = previous_ours
    return sonar_owner, ours_owner, remaining_work, False


def _security_match_variable_mask_rows(
    sonar_rows: list[dict[str, Any]],
    ours_rows: list[dict[str, Any]],
    remaining_work: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int, bool]:
    compatible, remaining_work, exhausted = _security_compatibility_graph(
        sonar_rows, ours_rows, remaining_work
    )
    if exhausted:
        return [], [], remaining_work, True
    sonar_owner, ours_owner, remaining_work, exhausted = (
        _security_assign_compatible_rows(
            compatible,
            len(sonar_rows),
            len(ours_rows),
            remaining_work,
        )
    )
    if exhausted:
        return [], [], remaining_work, True
    unmatched_sonar = [
        finding
        for index, finding in enumerate(sonar_rows)
        if sonar_owner[index] is None
    ]
    unmatched_ours = [
        finding for index, finding in enumerate(ours_rows) if ours_owner[index] is None
    ]
    return unmatched_sonar, unmatched_ours, remaining_work, False


def _security_match_detector_rows(
    sonar: list[dict[str, Any]], ours: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool, bool]:
    """Match compatible findings with a bounded deterministic work budget."""
    groups = _security_group_detector_rows(sonar, ours)
    unmatched_sonar: list[dict[str, Any]] = []
    unmatched_ours: list[dict[str, Any]] = []
    remaining_work = _SECURITY_COMPARISON_WORK_BUDGET
    exhausted = False
    known_mismatch = False
    for identity in sorted(groups, key=repr):
        sonar_rows, ours_rows = groups[identity]
        sonar_rows = sorted(
            sonar_rows, key=lambda finding: repr(_security_detector_key(finding))
        )
        ours_rows = sorted(
            ours_rows, key=lambda finding: repr(_security_detector_key(finding))
        )
        if not sonar_rows or not ours_rows:
            unmatched_sonar.extend(sonar_rows)
            unmatched_ours.extend(ours_rows)
            continue

        count_mismatch = len(sonar_rows) != len(ours_rows)
        if count_mismatch:
            known_mismatch = True
        uniform_rows = _security_uniform_detector_rows(sonar_rows, ours_rows)
        if uniform_rows is not None:
            missing, extra = uniform_rows
            unmatched_sonar.extend(missing)
            unmatched_ours.extend(extra)
            continue
        if count_mismatch:
            continue
        missing, extra, remaining_work, exhausted = _security_match_variable_mask_rows(
            sonar_rows, ours_rows, remaining_work
        )
        if exhausted:
            break
        unmatched_sonar.extend(missing)
        unmatched_ours.extend(extra)
    return unmatched_sonar, unmatched_ours, exhausted, known_mismatch


def _security_counter_rows(counter: Counter[tuple[Any, ...]]) -> list[dict[str, Any]]:
    rows = []
    for key, count in sorted(counter.items(), key=lambda item: repr(item[0])):
        rows.append(
            {
                "rule": key[0],
                "file": key[1],
                "message": key[2],
                "range": _thaw_security(key[3]),
                "detector": _thaw_security(key[4]),
                "count": count,
            }
        )
    return rows


def _security_review_rows(
    findings: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows = [
        {
            "rule": finding["rule"],
            "file": finding["file"],
            "range": finding["range"],
            "review": finding["review"],
        }
        for finding in findings
    ]
    return sorted(rows, key=lambda row: repr(row))


def _security_detector_available(findings: Iterable[dict[str, Any]]) -> bool:
    return all(
        detector["flow_evidence_available"]
        and detector["secondary_location_evidence_available"]
        and detector["primary_range_evidence_available"]
        for finding in findings
        for detector in (finding["detector"],)
    )


def compare_security_evidence(
    sonar_report: Any,
    ours_report: Any,
    *,
    expected_project: str | None = None,
) -> dict[str, Any]:
    """Compare detector evidence while reporting review state separately."""
    sonar = validate_security_evidence(sonar_report, expected_project=expected_project)
    ours = validate_security_evidence(ours_report, expected_project=expected_project)
    sonar_counter = Counter(_security_detector_key(finding) for finding in sonar)
    ours_counter = Counter(_security_detector_key(finding) for finding in ours)
    missing_rows, extra_rows, exhausted, known_mismatch = _security_match_detector_rows(
        sonar, ours
    )
    missing = Counter(_security_detector_key(finding) for finding in missing_rows)
    extra = Counter(_security_detector_key(finding) for finding in extra_rows)
    sonar_available = _security_detector_available(sonar)
    ours_available = _security_detector_available(ours)
    if missing or extra or known_mismatch:
        status = "BAD_MISMATCH"
    elif exhausted or not sonar_available or not ours_available:
        status = "SECURITY_EVIDENCE_UNAVAILABLE"
    else:
        status = "PASS"
    limits = sorted(
        set(sonar_report.get("limits", [])) | set(ours_report.get("limits", []))
    )
    if not sonar_available:
        limits.append("sonar detector evidence is incomplete")
    if not ours_available:
        limits.append("hoonarqube detector evidence is incomplete")
    if exhausted:
        limits.append("security detector comparison work budget exhausted")
    return {
        "schema_version": SECURITY_EVIDENCE_SCHEMA,
        "status": status,
        "detector": {
            "sonar": _security_counter_rows(sonar_counter),
            "ours": _security_counter_rows(ours_counter),
            "missing": _security_counter_rows(missing),
            "extra": _security_counter_rows(extra),
            "availability": {
                "sonar": sonar_available,
                "ours": ours_available,
            },
        },
        # Review status is deliberately visible but never part of detector
        # equality. A human changing OPEN/RESOLVED cannot turn a detector
        # mismatch into a pass, nor can it make equivalent detectors fail.
        "review": {
            "sonar": _security_review_rows(sonar),
            "ours": _security_review_rows(ours),
        },
        "limits": sorted(set(limits)),
    }


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


def _native_incomplete_details(
    report: Any,
) -> tuple[bool, str | None]:
    """Return whether native explicitly reports an incomplete project."""
    if not isinstance(report, dict):
        return False, None
    project = report.get("project")
    if not isinstance(project, dict) or project.get("complete") is not False:
        return False, None
    warnings = project.get("warnings")
    if isinstance(warnings, list):
        details = [warning for warning in warnings if isinstance(warning, str)]
        if details:
            return True, (
                "native project analysis is incomplete: " + "; ".join(details)
            )
    return True, "native project analysis is incomplete"


def _mark_native_incomplete(row: dict[str, Any], reason: str) -> None:
    observed_status = row.get("status")
    if observed_status is not None:
        row["observed_status"] = observed_status
    if "reason" in row:
        row["observed_reason"] = row["reason"]
    row["native_status"] = "INCOMPLETE"
    row["native_complete"] = False
    row["native_reason"] = reason
    row["status"] = "ORACLE_UNVERIFIED"
    row["reason"] = reason


def compare_reports(
    expected: list[dict[str, Any]],
    sonar_report: Any,
    hoonarqube_report: Any,
    infra: Mapping[str, str] | None = None,
    catalog_keys: Iterable[str] | None = None,
    available_files: Iterable[str] | None = None,
    enterprise_unverified: Iterable[str] = (),
) -> list[dict[str, Any]]:
    """Compare exact finding equality, never certifying an incomplete native report."""
    if not isinstance(expected, list):
        raise ValueError("oracle expectations must be a list")
    catalog = _unique_set(catalog_keys, "catalog key")
    files = _unique_set(available_files, "available fixture")
    native_incomplete, native_reason = _native_incomplete_details(hoonarqube_report)
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
        row = _comparison_row(expectation, counters, context)
        if native_incomplete:
            _mark_native_incomplete(
                row, native_reason or "native project analysis is incomplete"
            )
        rows.append(row)
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
    if native_incomplete and not rows:
        rows.append(
            _terminal_row(
                None,
                "ORACLE_UNVERIFIED",
                native_reason or "native project analysis is incomplete",
            )
        )
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
