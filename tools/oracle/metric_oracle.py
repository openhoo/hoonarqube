#!/usr/bin/env python3
"""Extract and compare SonarQube project metrics for the Hoonarqube oracle.

The tool intentionally keeps the reference side separate from Hoonarqube's
native report.  A run records the exact server, analyzer plugins, scanner image,
scanner properties, source bytes, component-tree pages, and duplication API
responses.  Missing metrics are represented as absent states; they are never
silently converted to zero.

Typical use (the token file is never copied to an artifact)::

    python3 tools/oracle/metric_oracle.py run \
      --corpus tools/oracle/fixtures/metrics/corpus.json \
      --output tools/oracle/metrics-reference.json \
      --url http://127.0.0.1:19084 \
      --token-file /path/to/sonar-token \
      --server-image-digest sha256:...

A native report can later be compared without contacting SonarQube::

    python3 tools/oracle/metric_oracle.py compare \
      --reference tools/oracle/metrics-reference.json \
      --native native-report.json \
      --output metrics-comparison.json
"""

from __future__ import annotations

import argparse
import base64
from collections.abc import Iterable, Mapping, Sequence
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request


SCHEMA_VERSION = 1
REFERENCE_KIND = "sonar-metrics-reference"
COMPARISON_KIND = "sonar-metrics-comparison"
DEFAULT_URL = "http://127.0.0.1:19084"
DEFAULT_SCANNER_IMAGE = (
    "docker.io/sonarsource/sonar-scanner-cli:12.1.0.3233_8.0.1@"
    "sha256:23ca0f137965d9dff2198074043fd48d386280bc5d0ccac8c8349cea4cf096a9"
)
METRIC_KEYS = (
    "lines",
    "ncloc",
    "comment_lines",
    "duplicated_lines",
    "duplicated_blocks",
    "duplicated_files",
    "duplicated_lines_density",
)
INTEGER_METRICS = frozenset(METRIC_KEYS[:-1])
DENSITY_METRIC = "duplicated_lines_density"

# These are the language families accepted by the current native project
# analyzer and by the reference corpus.  The plugin key is discovered from the
# server at run time; this table only maps scanner language identifiers.
SUPPORTED_LANGUAGES: dict[str, dict[str, Any]] = {
    "python": {"sonar_language": "py", "plugin": "python", "extensions": (".py",)},
    "javascript": {
        "sonar_language": "js",
        "plugin": "javascript",
        "extensions": (".js", ".jsx"),
    },
    "typescript": {
        "sonar_language": "ts",
        "plugin": "javascript",
        "extensions": (".ts", ".tsx"),
    },
    "csharp": {"sonar_language": "cs", "plugin": "csharp", "extensions": (".cs",)},
    "go": {"sonar_language": "go", "plugin": "go", "extensions": (".go",)},
    "java": {"sonar_language": "java", "plugin": "java", "extensions": (".java",)},
    "rust": {"sonar_language": "rust", "plugin": "rust", "extensions": (".rs",)},
    "ruby": {"sonar_language": "ruby", "plugin": "ruby", "extensions": (".rb",)},
}
UNSUPPORTED_LANGUAGE_STATUSES = frozenset({"UNSUPPORTED", "UNVERIFIED"})
PROJECT_KEY_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SENSITIVE_KEY_RE = re.compile(
    r"(?:password|secret|credential|(?:^|[._-])(?:token|login)(?:$|[._-]))",
    re.I,
)
TRANSIENT_HTTP_CODES = frozenset({429, 500, 502, 503, 504})


class MetricOracleError(RuntimeError):
    """A fail-closed metric extraction or comparison error."""


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant {value}")


def parse_json(text: str, *, context: str = "JSON") -> Any:
    if not isinstance(text, str):
        raise ValueError(f"{context} must be text")
    try:
        return json.loads(text, parse_constant=_reject_json_constant)
    except (json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"invalid {context}: {error}") from error


def read_json(path: str | os.PathLike[str]) -> Any:
    source = Path(path)
    try:
        return parse_json(
            source.read_text(encoding="utf-8"), context=f"JSON in {source}"
        )
    except (OSError, UnicodeError, ValueError) as error:
        raise ValueError(f"invalid JSON in {source}: {error}") from error


def _atomic_write(path: Path, rendered: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def write_json(
    path: str | os.PathLike[str], value: Any, *, indent: int | None = 2
) -> None:
    rendered = json.dumps(value, indent=indent, sort_keys=True, allow_nan=False) + "\n"
    _atomic_write(Path(path), rendered)


def _secret_file_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _validate_secret_file_metadata(metadata: os.stat_result, source: Path) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise MetricOracleError(f"token file must be regular: {source}")
    if os.name != "posix":
        return
    if metadata.st_uid != os.geteuid():
        raise MetricOracleError(f"token file must be owned by current user: {source}")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise MetricOracleError(
            f"token file permissions must not grant group/other access: {source}"
        )


def _read_secret_file(path: str | os.PathLike[str]) -> str:
    """Read an owner-only regular file without ever returning it to the caller."""
    source = Path(path)
    try:
        descriptor = os.open(source, _secret_file_flags())
    except OSError as error:
        raise MetricOracleError(
            f"cannot securely open token file {source}: {error}"
        ) from error
    try:
        _validate_secret_file_metadata(os.fstat(descriptor), source)
        with os.fdopen(descriptor, encoding="utf-8") as handle:
            descriptor = -1
            token = handle.read().strip()
    except (OSError, UnicodeError) as error:
        raise MetricOracleError(
            f"cannot securely read token file {source}: {error}"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not token:
        raise MetricOracleError("token file must not be empty")
    return token


def _redact(text: str, secret: str | None) -> str:
    if not secret:
        return text
    return text.replace(secret, "<redacted>")


def _validate_digest(value: str, *, label: str) -> str:
    if not isinstance(value, str) or not DIGEST_RE.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase sha256 digest")
    return value


def _image_digest(image: str) -> str:
    if not isinstance(image, str):
        raise ValueError("scanner image must be text")
    marker = image.rsplit("@", 1)
    if len(marker) != 2:
        raise ValueError("scanner image must be pinned by digest")
    return _validate_digest(marker[1], label="scanner image digest")


def _canonical_hash(value: Any) -> str:
    rendered = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    return hashlib.sha256(rendered).hexdigest()


def _validate_project_key(value: str, *, label: str = "project key") -> str:
    if not isinstance(value, str) or not value or not PROJECT_KEY_RE.fullmatch(value):
        raise ValueError(f"{label} contains unsupported characters")
    return value


def _relative_posix(path: Path, root: Path) -> str:
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise MetricOracleError(f"path {path} escapes fixture root {root}") from error
    return relative.as_posix()


def source_inventory(root: str | os.PathLike[str]) -> dict[str, Any]:
    """Return deterministic byte-level hashes for a fixture directory."""
    source_root = Path(root).resolve()
    if not source_root.is_dir() or source_root.is_symlink():
        raise ValueError(
            f"fixture source directory must be a real directory: {source_root}"
        )
    records: list[dict[str, Any]] = []
    for path in sorted(source_root.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            raise ValueError(f"fixture source must not contain symlinks: {path}")
        if not path.is_file():
            continue
        relative = _relative_posix(path, source_root)
        data = path.read_bytes()
        records.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
            }
        )
    digest = hashlib.sha256()
    for record in records:
        name = record["path"].encode("utf-8")
        data = (source_root / record["path"]).read_bytes()
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return {
        "root": source_root.name,
        "files": records,
        "file_count": len(records),
        "sha256": digest.hexdigest(),
    }


def _safe_properties(properties: Mapping[str, Any]) -> dict[str, str]:
    if not isinstance(properties, Mapping):
        raise ValueError("scanner properties must be an object")
    result: dict[str, str] = {}
    for key, value in properties.items():
        if not isinstance(key, str) or not key or SENSITIVE_KEY_RE.search(key):
            raise ValueError(f"scanner property {key!r} is sensitive or invalid")
        if not isinstance(value, (str, int, float, bool)):
            raise ValueError(f"scanner property {key!r} must be scalar")
        result[key] = str(value)
    return result


def _validate_corpus_case_identity(
    case: Any, index: int, seen: set[str]
) -> tuple[str, Any, str]:
    if not isinstance(case, Mapping):
        raise ValueError(f"metric corpus case {index} must be an object")
    case_id = case.get("id")
    if not isinstance(case_id, str) or not case_id or case_id in seen:
        raise ValueError(f"metric corpus case {index} has duplicate/invalid id")
    seen.add(case_id)
    language = case.get("language")
    if language not in SUPPORTED_LANGUAGES:
        raise ValueError(
            f"metric corpus case {case_id} has unsupported language {language!r}"
        )
    source_dir = case.get("source_dir")
    if (
        not isinstance(source_dir, str)
        or not source_dir
        or Path(source_dir).is_absolute()
    ):
        raise ValueError(f"metric corpus case {case_id} source_dir must be relative")
    return case_id, language, source_dir


def _validate_corpus_case_source(
    case_id: str, source_dir: str, corpus_root: Path | None
) -> None:
    if corpus_root is None:
        return
    source = (corpus_root / source_dir).resolve()
    try:
        source.relative_to(corpus_root)
    except ValueError as error:
        raise ValueError(
            f"metric corpus case {case_id} source_dir escapes root"
        ) from error
    if not source.is_dir() or source.is_symlink():
        raise ValueError(
            f"metric corpus case {case_id} source_dir does not exist: {source}"
        )


def _validate_corpus_case_options(case: Mapping[str, Any], case_id: str) -> None:
    scan = case.get("scan", True)
    if not isinstance(scan, bool):
        raise ValueError(f"metric corpus case {case_id} scan must be boolean")
    if not scan and (
        not isinstance(case.get("reason"), str) or not case["reason"].strip()
    ):
        raise ValueError(
            f"metric corpus case {case_id} requires a reason when scan=false"
        )
    sources = case.get("sources", "src")
    if not isinstance(sources, str) or not sources:
        raise ValueError(f"metric corpus case {case_id} sources must be non-empty text")
    tests = case.get("tests")
    if tests is not None and (not isinstance(tests, str) or not tests):
        raise ValueError(f"metric corpus case {case_id} tests must be text")
    _safe_properties(case.get("properties", {}))
    expected_features = case.get("features", [])
    if not isinstance(expected_features, list) or not all(
        isinstance(feature, str) and feature for feature in expected_features
    ):
        raise ValueError(f"metric corpus case {case_id} features must be text list")


def _validate_csharp_corpus_files(
    case: Mapping[str, Any],
    case_id: str,
    language: Any,
    source_dir: str,
    corpus_root: Path | None,
) -> None:
    if language != "csharp":
        return
    project_file = case.get("project_file")
    solution_file = case.get("solution_file")
    if not isinstance(project_file, str) or Path(project_file).is_absolute():
        raise ValueError(f"metric corpus case {case_id} project_file must be relative")
    if not isinstance(solution_file, str) or Path(solution_file).is_absolute():
        raise ValueError(f"metric corpus case {case_id} solution_file must be relative")
    if corpus_root is None:
        return
    if not (corpus_root / source_dir / project_file).is_file():
        raise ValueError(f"metric corpus case {case_id} project_file does not exist")
    if not (corpus_root / source_dir / solution_file).is_file():
        raise ValueError(f"metric corpus case {case_id} solution_file does not exist")


def _validate_corpus_case(
    case: Any, index: int, seen: set[str], corpus_root: Path | None
) -> None:
    case_id, language, source_dir = _validate_corpus_case_identity(case, index, seen)
    _validate_corpus_case_source(case_id, source_dir, corpus_root)
    _validate_corpus_case_options(case, case_id)
    _validate_csharp_corpus_files(case, case_id, language, source_dir, corpus_root)


def _validate_unsupported_corpus_row(
    row: Any, seen: set[str], seen_unsupported: set[str]
) -> None:
    if not isinstance(row, Mapping):
        raise ValueError("metric corpus unsupported rows must be objects")
    row_id = row.get("id")
    if (
        not isinstance(row_id, str)
        or not row_id
        or row_id in seen
        or row_id in seen_unsupported
    ):
        raise ValueError(
            f"metric corpus unsupported id {row_id!r} is duplicate/invalid"
        )
    seen_unsupported.add(row_id)
    status = row.get("status")
    if status not in UNSUPPORTED_LANGUAGE_STATUSES:
        raise ValueError(f"metric corpus unsupported {row_id} has invalid status")
    reason = row.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError(f"metric corpus unsupported {row_id} requires a reason")


def validate_corpus(
    corpus: Mapping[str, Any], *, root: str | os.PathLike[str] | None = None
) -> None:
    """Validate the versioned manifest before any scanner/API side effect."""
    if not isinstance(corpus, Mapping):
        raise ValueError("metric corpus must be an object")
    if corpus.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"metric corpus schema_version must be {SCHEMA_VERSION}")
    corpus_id = corpus.get("corpus_id")
    if not isinstance(corpus_id, str) or not corpus_id.strip():
        raise ValueError("metric corpus corpus_id must be non-empty")
    cases = corpus.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("metric corpus cases must be a non-empty list")
    seen: set[str] = set()
    corpus_root = Path(root).resolve() if root is not None else None
    for index, case in enumerate(cases):
        _validate_corpus_case(case, index, seen, corpus_root)
    unsupported = corpus.get("unsupported", [])
    if not isinstance(unsupported, list):
        raise ValueError("metric corpus unsupported must be a list")
    seen_unsupported: set[str] = set()
    for row in unsupported:
        _validate_unsupported_corpus_row(row, seen, seen_unsupported)


def load_corpus(path: str | os.PathLike[str]) -> tuple[dict[str, Any], Path]:
    manifest = Path(path).resolve()
    corpus = read_json(manifest)
    root = manifest.parent
    validate_corpus(corpus, root=root)
    return dict(corpus), root


class SonarApi:
    """Small authenticated JSON client with bounded transient retries."""

    def __init__(
        self, base_url: str, token: str, *, timeout: float = 30.0, retries: int = 3
    ):
        if not isinstance(base_url, str) or not base_url.startswith(
            ("http://", "https://")
        ):
            raise ValueError("Sonar URL must be http(s)")
        if not token:
            raise ValueError("Sonar token must not be empty")
        self.base_url = base_url.rstrip("/")
        self._token = token
        self.timeout = timeout
        self.retries = max(0, retries)

    def get(self, path: str, params: Mapping[str, Any] | None = None) -> Any:
        if not path.startswith("/"):
            raise ValueError("Sonar API path must start with '/'")
        query = urllib.parse.urlencode(params or {})
        target = f"{self.base_url}{path}{'?' + query if query else ''}"
        request = urllib.request.Request(target, method="GET")
        encoded = base64.b64encode(f"{self._token}:".encode("utf-8")).decode("ascii")
        request.add_header("Authorization", f"Basic {encoded}")
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    raw = response.read()
                return (
                    parse_json(raw.decode("utf-8"), context=f"Sonar API {path}")
                    if raw
                    else {}
                )
            except urllib.error.HTTPError as error:
                last_error = error
                if error.code not in TRANSIENT_HTTP_CODES or attempt == self.retries:
                    raise MetricOracleError(
                        f"Sonar API {path} returned HTTP {error.code}"
                    ) from error
            except (
                urllib.error.URLError,
                TimeoutError,
                OSError,
                UnicodeError,
            ) as error:
                last_error = error
                if attempt == self.retries:
                    raise MetricOracleError(f"Sonar API {path} unavailable") from error
            time.sleep(min(5.0, 0.5 * (attempt + 1)))
        raise MetricOracleError(f"Sonar API {path} failed") from last_error


def discover_server_provenance(
    api: SonarApi, *, image_digest: str | None = None
) -> dict[str, Any]:
    status = api.get("/api/system/status")
    if not isinstance(status, Mapping) or status.get("status") != "UP":
        raise MetricOracleError("reference Sonar server is not UP")
    plugins_payload = api.get("/api/plugins/installed")
    plugins = (
        plugins_payload.get("plugins") if isinstance(plugins_payload, Mapping) else None
    )
    if not isinstance(plugins, list):
        raise MetricOracleError("Sonar plugin response lacks plugins list")
    stable_plugins: list[dict[str, Any]] = []
    for plugin in plugins:
        if not isinstance(plugin, Mapping) or not isinstance(plugin.get("key"), str):
            raise MetricOracleError("Sonar plugin response contains malformed plugin")
        stable_plugins.append(
            {
                "key": plugin["key"],
                "name": plugin.get("name"),
                "version": plugin.get("version"),
                "implementationBuild": plugin.get("implementationBuild"),
                "hash": plugin.get("hash"),
                "filename": plugin.get("filename"),
                "requiredForLanguages": plugin.get("requiredForLanguages", []),
                "editionBundled": plugin.get("editionBundled"),
            }
        )
    stable_plugins.sort(key=lambda item: item["key"])
    result: dict[str, Any] = {
        "id": status.get("id"),
        "version": status.get("version"),
        "status": status.get("status"),
        "plugins": stable_plugins,
    }
    if image_digest is not None:
        result["image_digest"] = _validate_digest(
            image_digest, label="server image digest"
        )
    else:
        result["image_digest"] = None
    return result


def _plugin_map(server: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    plugins = server.get("plugins")
    if not isinstance(plugins, list):
        raise ValueError("server provenance plugins must be a list")
    return {
        item["key"]: item
        for item in plugins
        if isinstance(item, Mapping) and isinstance(item.get("key"), str)
    }


def _parse_numeric_metric(metric: str, value: Any) -> int | float:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Sonar metric {metric} value must be a non-empty string")
    if metric in INTEGER_METRICS:
        if not re.fullmatch(r"[0-9]+", value):
            raise ValueError(f"Sonar metric {metric} is not an unsigned integer")
        return int(value)
    try:
        number = float(value)
    except ValueError as error:
        raise ValueError(f"Sonar metric {metric} is not numeric") from error
    if number != number or number in (float("inf"), float("-inf")):
        raise ValueError(f"Sonar metric {metric} is not finite")
    return number


def normalize_component_measures(
    component: Mapping[str, Any], *, project: bool = False
) -> dict[str, Any]:
    if not isinstance(component, Mapping):
        raise ValueError("Sonar component must be an object")
    measures = component.get("measures", [])
    if not isinstance(measures, list):
        raise ValueError("Sonar component measures must be a list")
    values: dict[str, int | float | None] = {metric: None for metric in METRIC_KEYS}
    states: dict[str, str] = {metric: "ABSENT" for metric in METRIC_KEYS}
    raw_by_metric: dict[str, dict[str, Any]] = {}
    for index, measure in enumerate(measures):
        if not isinstance(measure, Mapping):
            raise ValueError(f"Sonar measure {index} must be an object")
        metric = measure.get("metric")
        if metric not in METRIC_KEYS:
            continue
        if metric in raw_by_metric:
            raise ValueError(f"Sonar component repeats metric {metric}")
        raw_by_metric[metric] = dict(measure)
        if "value" not in measure:
            continue
        values[metric] = _parse_numeric_metric(metric, measure["value"])
        states[metric] = "PRESENT"
    if project and states[DENSITY_METRIC] == "ABSENT" and values["lines"] in (None, 0):
        states[DENSITY_METRIC] = "NO_DENOMINATOR"
    return {
        "metrics": values,
        "metric_states": states,
        "raw_measures": raw_by_metric,
    }


def fetch_project_measures(api: SonarApi, project_key: str) -> dict[str, Any]:
    project_key = _validate_project_key(project_key)
    payload = api.get(
        "/api/measures/component",
        {"component": project_key, "metricKeys": ",".join(METRIC_KEYS)},
    )
    component = payload.get("component") if isinstance(payload, Mapping) else None
    if not isinstance(component, Mapping) or component.get("key") != project_key:
        raise MetricOracleError("project measures response has wrong component")
    normalized = normalize_component_measures(component, project=True)
    return {"component": dict(component), **normalized, "raw": payload}


def _validate_paging(
    paging: Any, *, page: int, expected_total: int | None, expected_size: int | None
) -> tuple[int, int]:
    if not isinstance(paging, Mapping):
        raise ValueError("Sonar component tree lacks paging")
    if paging.get("pageIndex") != page:
        raise ValueError("Sonar component tree returned an unexpected page index")
    size = paging.get("pageSize")
    total = paging.get("total")
    if (
        not isinstance(size, int)
        or size <= 0
        or not isinstance(total, int)
        or total < 0
    ):
        raise ValueError("Sonar component tree paging is invalid")
    if expected_total is not None and total != expected_total:
        raise ValueError("Sonar component tree total changed while paging")
    if expected_size is not None and size != expected_size:
        raise ValueError("Sonar component tree page size changed while paging")
    return total, size


def _normalize_file_measure_component(
    component: Any, index: int, project_key: str, seen_keys: set[str]
) -> dict[str, Any]:
    if not isinstance(component, Mapping):
        raise ValueError(f"Sonar component tree file {index} must be an object")
    key = component.get("key")
    if not isinstance(key, str) or not key.startswith(f"{project_key}:"):
        raise ValueError("Sonar component tree file has wrong project key")
    if key in seen_keys:
        raise ValueError(f"Sonar component tree repeats file {key}")
    if component.get("qualifier") != "FIL":
        raise ValueError("Sonar component tree returned a non-file qualifier")
    seen_keys.add(key)
    normalized = normalize_component_measures(component)
    return {
        "key": key,
        "name": component.get("name"),
        "path": component.get("path"),
        "qualifier": component.get("qualifier"),
        "language": component.get("language"),
        "metrics": normalized["metrics"],
        "metric_states": normalized["metric_states"],
        "raw_measures": normalized["raw_measures"],
        "raw": dict(component),
    }


def _fetch_file_measure_page(
    api: SonarApi,
    project_key: str,
    *,
    page: int,
    page_size: int,
    expected_total: int | None,
    expected_size: int | None,
    seen_keys: set[str],
) -> tuple[Mapping[str, Any], int, int, list[dict[str, Any]]]:
    payload = api.get(
        "/api/measures/component_tree",
        {
            "component": project_key,
            "metricKeys": ",".join(METRIC_KEYS),
            "qualifiers": "FIL",
            "ps": page_size,
            "p": page,
        },
    )
    if not isinstance(payload, Mapping):
        raise ValueError("Sonar component tree response must be an object")
    total, size = _validate_paging(
        payload.get("paging"),
        page=page,
        expected_total=expected_total,
        expected_size=expected_size,
    )
    page_components = payload.get("components")
    if not isinstance(page_components, list):
        raise ValueError("Sonar component tree components must be a list")
    normalized_page = [
        _normalize_file_measure_component(component, index, project_key, seen_keys)
        for index, component in enumerate(page_components)
    ]
    return payload, total, size, normalized_page


def fetch_file_measures(
    api: SonarApi, project_key: str, *, page_size: int = 100
) -> dict[str, Any]:
    project_key = _validate_project_key(project_key)
    if not isinstance(page_size, int) or not 1 <= page_size <= 500:
        raise ValueError("file measure page_size must be between 1 and 500")
    components: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    page = 1
    expected_total = expected_size = None
    pages: list[dict[str, Any]] = []
    while True:
        payload, total, size, normalized_page = _fetch_file_measure_page(
            api,
            project_key,
            page=page,
            page_size=page_size,
            expected_total=expected_total,
            expected_size=expected_size,
            seen_keys=seen_keys,
        )
        if expected_total is None:
            expected_total, expected_size = total, size
        components.extend(normalized_page)
        pages.append(
            {"page": page, "count": len(normalized_page), "raw": dict(payload)}
        )
        if len(components) >= total:
            if len(components) != total:
                raise ValueError(
                    "Sonar component tree returned more files than paging total"
                )
            break
        if not normalized_page:
            raise ValueError("Sonar component tree ended before paging total")
        page += 1
    return {
        "paging": {"total": expected_total, "page_size": expected_size, "pages": pages},
        "files": components,
    }


def _component_path(info: Mapping[str, Any], *, project_key: str) -> str:
    name = info.get("path") or info.get("name")
    if isinstance(name, str) and name:
        normalized = name.replace("\\", "/")
        prefix = f"{project_key}:"
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :]
        return normalized.lstrip("./")
    key = info.get("key")
    if isinstance(key, str) and key.startswith(f"{project_key}:"):
        return key[len(project_key) + 1 :]
    raise ValueError("Sonar duplicate file lacks a path")


def normalize_duplicate_payload(
    payload: Mapping[str, Any], *, project_key: str
) -> dict[str, Any]:
    duplications = payload.get("duplications")
    files = payload.get("files")
    if not isinstance(duplications, list) or not isinstance(files, Mapping):
        raise ValueError("Sonar duplication response lacks duplications/files")
    occurrences: list[dict[str, Any]] = []
    groups: list[dict[str, Any]] = []
    for group_index, duplication in enumerate(duplications):
        if not isinstance(duplication, Mapping) or not isinstance(
            duplication.get("blocks"), list
        ):
            raise ValueError(f"Sonar duplication group {group_index} is malformed")
        group_occurrences: list[dict[str, Any]] = []
        for block_index, block in enumerate(duplication["blocks"]):
            if not isinstance(block, Mapping):
                raise ValueError("Sonar duplicate block must be an object")
            reference = block.get("_ref")
            start = block.get("from")
            size = block.get("size")
            if not isinstance(reference, str) or not reference:
                raise ValueError("Sonar duplicate block lacks _ref")
            if (
                not isinstance(start, int)
                or start < 1
                or not isinstance(size, int)
                or size < 1
            ):
                raise ValueError("Sonar duplicate block has invalid line range")
            info = files.get(reference)
            if not isinstance(info, Mapping):
                raise ValueError(
                    f"Sonar duplicate block references unknown file {reference}"
                )
            key = info.get("key")
            if not isinstance(key, str) or not key.startswith(f"{project_key}:"):
                raise ValueError("Sonar duplicate block references another project")
            occurrence = {
                "group": group_index,
                "block": block_index,
                "reference": reference,
                "file_key": key,
                "path": _component_path(info, project_key=project_key),
                "start_line": start,
                "end_line": start + size - 1,
                "line_count": size,
            }
            occurrences.append(occurrence)
            group_occurrences.append(occurrence)
        groups.append({"group": group_index, "occurrences": group_occurrences})
    return {"groups": groups, "occurrences": occurrences}


def fetch_duplicate_evidence(
    api: SonarApi, project_key: str, files: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    project_key = _validate_project_key(project_key)
    evidence: list[dict[str, Any]] = []
    for component in files:
        file_key = component.get("key") if isinstance(component, Mapping) else None
        if not isinstance(file_key, str) or not file_key.startswith(f"{project_key}:"):
            raise ValueError("duplicate evidence file key is not in project")
        payload = api.get("/api/duplications/show", {"key": file_key})
        normalized = normalize_duplicate_payload(payload, project_key=project_key)
        evidence.append({"file_key": file_key, **normalized, "raw": payload})
    return evidence


def _read_report_task(path: Path, *, project_key: str) -> str:
    try:
        rows = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise MetricOracleError(
            f"cannot read scanner report-task file {path}"
        ) from error
    values: dict[str, str] = {}
    for row in rows:
        if "=" in row:
            key, value = row.split("=", 1)
            values[key] = value
    if values.get("projectKey") != project_key or not values.get("ceTaskId"):
        raise MetricOracleError("scanner report-task has wrong project or no CE task")
    return values["ceTaskId"]


def _scanner_version(output: str, *, dotnet: bool = False) -> str | None:
    pattern = (
        r"SonarScanner for \.NET\s+([^\s]+)"
        if dotnet
        else r"SonarScanner CLI\s+([^\s]+)"
    )
    match = re.search(pattern, output)
    return match.group(1) if match else None


def _run_subprocess(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout: int,
    secret: str,
) -> tuple[subprocess.CompletedProcess[str], str]:
    try:
        result = subprocess.run(
            list(command),
            cwd=cwd,
            env=dict(env),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise MetricOracleError(f"scanner timed out after {timeout}s") from error
    combined = _redact((result.stdout or "") + "\n" + (result.stderr or ""), secret)
    return result, combined


def _generic_config(
    case: Mapping[str, Any], project_key: str, url: str
) -> dict[str, str]:
    config = {
        "sonar.projectKey": project_key,
        "sonar.host.url": url,
        "sonar.projectBaseDir": "/usr/src",
        "sonar.sources": str(case.get("sources", "src")),
        "sonar.scm.disabled": "true",
    }
    tests = case.get("tests")
    if tests:
        config["sonar.tests"] = str(tests)
    config.update(_safe_properties(case.get("properties", {})))
    return config


def _config_arguments(config: Mapping[str, str]) -> list[str]:
    return [f"-D{key}={config[key]}" for key in sorted(config)]


def _run_generic_scan(
    case: Mapping[str, Any],
    project_key: str,
    source_root: Path,
    url: str,
    token: str,
    scanner_image: str,
    timeout: int,
) -> dict[str, Any]:
    podman = shutil.which("podman")
    if podman is None:
        raise MetricOracleError("podman is required for generic Sonar scanner runs")
    digest = _image_digest(scanner_image)
    config = _generic_config(case, project_key, url)
    with tempfile.TemporaryDirectory(
        prefix=f"hq45-scanner-{project_key}-"
    ) as working_name:
        working = Path(working_name)
        command = [
            podman,
            "run",
            "--rm",
            "--userns=keep-id",
            "--network",
            "host",
            "-e",
            "SONAR_HOST_URL",
            "-e",
            "SONAR_TOKEN",
            "-v",
            f"{source_root.resolve()}:/usr/src:Z",
            "-v",
            f"{working}:/tmp/scannerwork:Z",
            "-w",
            "/usr/src",
            scanner_image,
            *(
                _config_arguments(config)
                + ["-Dsonar.working.directory=/tmp/scannerwork"]
            ),
        ]
        environment = dict(os.environ)
        environment["SONAR_HOST_URL"] = url
        environment["SONAR_TOKEN"] = token
        result, output = _run_subprocess(
            command, cwd=source_root, env=environment, timeout=timeout, secret=token
        )
        if result.returncode != 0 or "EXECUTION SUCCESS" not in output:
            raise MetricOracleError(
                f"generic scanner failed with exit {result.returncode}: {output[-2000:]}"
            )
        task_id = _read_report_task(
            working / "report-task.txt", project_key=project_key
        )
    return {
        "mode": "sonar-scanner-cli",
        "image": scanner_image,
        "image_digest": digest,
        "version": _scanner_version(output),
        "project_key": project_key,
        "properties": config,
        "properties_sha256": _canonical_hash(config),
        "task_id": task_id,
        "exit_code": result.returncode,
    }


def _dotnet_scanner_path() -> str:
    configured = os.environ.get("SONAR_DOTNET_SCANNER", "dotnet-sonarscanner")
    found = shutil.which(configured) if os.path.sep not in configured else configured
    if found and Path(found).is_file():
        return found
    fallback = Path.home() / ".dotnet/tools/dotnet-sonarscanner"
    if fallback.is_file():
        return str(fallback)
    raise MetricOracleError("dotnet-sonarscanner is required for C# reference runs")


def _run_csharp_scan(
    case: Mapping[str, Any],
    project_key: str,
    source_root: Path,
    url: str,
    token: str,
    timeout: int,
) -> dict[str, Any]:
    scanner = _dotnet_scanner_path()
    project_file = case.get("project_file")
    solution_file = case.get("solution_file")
    if not isinstance(project_file, str) or not isinstance(solution_file, str):
        raise MetricOracleError(
            "C# metric case requires project_file and solution_file"
        )
    properties = _safe_properties(case.get("properties", {}))
    properties.update(
        {
            "sonar.projectKey": project_key,
            "sonar.host.url": url,
            "sonar.projectBaseDir": str(source_root.resolve()),
            "sonar.scm.exclusions.disabled": "true",
        }
    )
    with tempfile.TemporaryDirectory(
        prefix=f"hq45-csharp-{project_key}-", dir=source_root.parent
    ) as temp_name:
        temporary_root = Path(temp_name)
        shutil.copytree(source_root, temporary_root / "source", dirs_exist_ok=True)
        worktree = temporary_root / "source"
        solution = worktree / solution_file
        begin = [
            scanner,
            "begin",
            f"/k:{project_key}",
            f"/d:sonar.host.url={url}",
            f"/d:sonar.projectBaseDir={worktree}",
            "/d:sonar.scm.exclusions.disabled=true",
            f"/d:sonar.token={token}",
        ]
        begin.extend(
            f"/d:{key}={value}"
            for key, value in sorted(properties.items())
            if key
            not in {
                "sonar.projectKey",
                "sonar.host.url",
                "sonar.projectBaseDir",
                "sonar.scm.exclusions.disabled",
            }
        )
        environment = dict(os.environ)
        environment["SONAR_HOST_URL"] = url
        began = False
        try:
            begin_result, begin_output = _run_subprocess(
                begin, cwd=worktree, env=environment, timeout=timeout, secret=token
            )
            if begin_result.returncode != 0:
                raise MetricOracleError(
                    f"C# scanner begin failed: {begin_output[-2000:]}"
                )
            began = True
            build_result, build_output = _run_subprocess(
                ["dotnet", "build", str(solution), "--nologo"],
                cwd=worktree,
                env=environment,
                timeout=timeout,
                secret=token,
            )
            if build_result.returncode != 0:
                raise MetricOracleError(f"C# build failed: {build_output[-2000:]}")
        finally:
            if began:
                end_result, end_output = _run_subprocess(
                    [scanner, "end", f"/d:sonar.token={token}"],
                    cwd=worktree,
                    env=environment,
                    timeout=timeout,
                    secret=token,
                )
                if end_result.returncode != 0:
                    raise MetricOracleError(
                        f"C# scanner end failed: {end_output[-2000:]}"
                    )
        task_id = _read_report_task(
            worktree / ".sonarqube/out/.sonar/report-task.txt", project_key=project_key
        )
    version_result = subprocess.run(
        [scanner, "--version"], capture_output=True, text=True, timeout=60
    )
    version = _scanner_version(
        (version_result.stdout or "") + "\n" + (version_result.stderr or ""),
        dotnet=True,
    )
    return {
        "mode": "dotnet-sonarscanner",
        "path": scanner,
        "version": version,
        "project_key": project_key,
        "properties": properties,
        "properties_sha256": _canonical_hash(properties),
        "task_id": task_id,
        "exit_code": 0,
    }


def wait_for_compute_engine(api: SonarApi, task_id: str, *, timeout: int = 900) -> str:
    if not isinstance(task_id, str) or not task_id:
        raise ValueError("CE task id must be non-empty")
    deadline = time.monotonic() + timeout
    while True:
        payload = api.get("/api/ce/task", {"id": task_id})
        task = payload.get("task") if isinstance(payload, Mapping) else None
        status = task.get("status") if isinstance(task, Mapping) else None
        if status in {"SUCCESS", "FAILED", "CANCELED"}:
            return str(status)
        if status not in {"PENDING", "IN_PROGRESS"}:
            raise MetricOracleError(f"unknown Sonar CE status {status!r}")
        if time.monotonic() >= deadline:
            raise MetricOracleError(f"Sonar CE task {task_id} timed out")
        time.sleep(1.0)


def _case_key(prefix: str, case_id: str) -> str:
    key = f"{prefix}-{case_id}"
    return _validate_project_key(key, label="derived project key")


def _ensure_project(api: SonarApi, project_key: str) -> None:
    projects = api.get("/api/projects/search", {"projects": project_key})
    components = projects.get("components") if isinstance(projects, Mapping) else None
    if isinstance(components, list) and any(
        isinstance(component, Mapping) and component.get("key") == project_key
        for component in components
    ):
        return
    body = urllib.parse.urlencode({"project": project_key, "name": project_key}).encode(
        "utf-8"
    )
    request = urllib.request.Request(
        f"{api.base_url}/api/projects/create", data=body, method="POST"
    )
    encoded = base64.b64encode(f"{api._token}:".encode("utf-8")).decode("ascii")
    request.add_header("Authorization", f"Basic {encoded}")
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(request, timeout=api.timeout):
            pass
    except urllib.error.HTTPError as error:
        if error.code == 400:
            # A concurrent owner may have created the intentionally unique key.
            check = api.get("/api/projects/search", {"projects": project_key})
            found = check.get("components") if isinstance(check, Mapping) else None
            if isinstance(found, list) and any(
                isinstance(component, Mapping) and component.get("key") == project_key
                for component in found
            ):
                return
        raise MetricOracleError(f"cannot create Sonar project {project_key}") from error


def _extract_case(
    api: SonarApi,
    case: Mapping[str, Any],
    *,
    corpus_root: Path,
    project_key: str,
    url: str,
    token: str,
    scanner_image: str,
    page_size: int,
    scan_timeout: int,
    ce_timeout: int,
) -> dict[str, Any]:
    source_root = (corpus_root / str(case["source_dir"])).resolve()
    inventory = source_inventory(source_root)
    properties = _safe_properties(case.get("properties", {}))
    language_info = SUPPORTED_LANGUAGES[case["language"]]
    result: dict[str, Any] = {
        "id": case["id"],
        "language": case["language"],
        "analyzer": {
            "sonar_language": language_info["sonar_language"],
            "plugin": language_info["plugin"],
        },
        "project_key": project_key,
        "source_dir": str(case["source_dir"]),
        "source_sha256": inventory["sha256"],
        "source": inventory,
        "features": list(case.get("features", [])),
        "scope": {
            "sources": case.get("sources", "src"),
            "tests": case.get("tests"),
            "project_file": case.get("project_file"),
            "solution_file": case.get("solution_file"),
            "properties": properties,
            "properties_sha256": _canonical_hash(properties),
        },
    }
    _ensure_project(api, project_key)
    scanner = (
        _run_csharp_scan(case, project_key, source_root, url, token, scan_timeout)
        if case["language"] == "csharp"
        else _run_generic_scan(
            case, project_key, source_root, url, token, scanner_image, scan_timeout
        )
    )
    result["scanner"] = scanner
    ce_status = wait_for_compute_engine(api, scanner["task_id"], timeout=ce_timeout)
    result["compute_engine"] = {"task_id": scanner["task_id"], "status": ce_status}
    if ce_status != "SUCCESS":
        result.update(
            {"status": "INCOMPLETE", "reason": f"Sonar compute engine {ce_status}"}
        )
        return result
    project = fetch_project_measures(api, project_key)
    files = fetch_file_measures(api, project_key, page_size=page_size)
    duplicates = fetch_duplicate_evidence(api, project_key, files["files"])
    result.update(
        {
            "status": "COMPLETE",
            "project": project,
            "files": files,
            "duplicates": duplicates,
        }
    )
    return result


def _case_provenance(case: Mapping[str, Any], *, corpus_root: Path) -> dict[str, Any]:
    source_root = (corpus_root / str(case["source_dir"])).resolve()
    inventory = source_inventory(source_root)
    properties = _safe_properties(case.get("properties", {}))
    language_info = SUPPORTED_LANGUAGES[case["language"]]
    return {
        "id": case["id"],
        "language": case["language"],
        "analyzer": {
            "sonar_language": language_info["sonar_language"],
            "plugin": language_info["plugin"],
        },
        "source_dir": str(case["source_dir"]),
        "source_sha256": inventory["sha256"],
        "source": inventory,
        "features": list(case.get("features", [])),
        "scope": {
            "sources": case.get("sources", "src"),
            "tests": case.get("tests"),
            "project_file": case.get("project_file"),
            "solution_file": case.get("solution_file"),
            "properties": properties,
            "properties_sha256": _canonical_hash(properties),
        },
    }


def _validate_selected_cases(
    corpus: Mapping[str, Any], selected_cases: Iterable[str] | None
) -> set[str] | None:
    selected = set(selected_cases) if selected_cases is not None else None
    available = {case["id"] for case in corpus["cases"]}
    if selected is not None and not selected <= available:
        unknown = sorted(selected - available)
        raise ValueError(f"unknown metric corpus case(s): {', '.join(unknown)}")
    return selected


def _extract_reference_case(
    api: SonarApi,
    case: Mapping[str, Any],
    *,
    corpus_root: Path,
    project_prefix: str,
    url: str,
    token: str,
    plugins: Mapping[str, Any],
    scanner_image: str,
    page_size: int,
    scan_timeout: int,
    ce_timeout: int,
) -> dict[str, Any]:
    base = _case_provenance(case, corpus_root=corpus_root)
    project_key = _case_key(project_prefix, case["id"])
    if not case.get("scan", True):
        return {
            **base,
            "project_key": project_key,
            "status": "UNVERIFIED",
            "reason": case["reason"],
        }
    plugin_key = SUPPORTED_LANGUAGES[case["language"]]["plugin"]
    if plugin_key not in plugins:
        return {
            **base,
            "project_key": project_key,
            "status": "UNVERIFIED",
            "reason": f"reference analyzer plugin {plugin_key} is not installed",
        }
    try:
        return _extract_case(
            api,
            case,
            corpus_root=corpus_root,
            project_key=project_key,
            url=url,
            token=token,
            scanner_image=scanner_image,
            page_size=page_size,
            scan_timeout=scan_timeout,
            ce_timeout=ce_timeout,
        )
    except Exception as error:
        # The case is retained as an explicit incomplete result; no metric
        # zeros are synthesized and remaining independent cases continue.
        return {
            **base,
            "project_key": project_key,
            "status": "INCOMPLETE",
            "reason": str(error),
        }


def _unsupported_reference_rows(
    rows: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    unsupported = []
    for row in rows:
        metrics = {
            metric: {"status": "UNVERIFIED", "reason": row["reason"]}
            for metric in METRIC_KEYS
        }
        unsupported.append({**dict(row), "metrics": metrics})
    return unsupported


def _reference_corpus_provenance(
    corpus_path: str | os.PathLike[str], corpus: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "id": corpus["corpus_id"],
        "schema_version": corpus["schema_version"],
        "manifest": str(Path(corpus_path).resolve().relative_to(Path.cwd().resolve()))
        if Path(corpus_path).resolve().is_relative_to(Path.cwd().resolve())
        else str(Path(corpus_path).resolve()),
        "manifest_sha256": hashlib.sha256(Path(corpus_path).read_bytes()).hexdigest(),
    }


def extract_reference(
    corpus_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str] | None = None,
    *,
    url: str | None = None,
    token: str | None = None,
    token_file: str | os.PathLike[str] | None = None,
    project_prefix: str = "hq45-metrics",
    scanner_image: str = DEFAULT_SCANNER_IMAGE,
    server_image_digest: str | None = None,
    selected_cases: Iterable[str] | None = None,
    page_size: int = 3,
    scan_timeout: int = 1800,
    ce_timeout: int = 900,
) -> dict[str, Any]:
    """Run Sonar extraction for selected corpus cases and return the artifact."""
    corpus, corpus_root = load_corpus(corpus_path)
    url = (url or os.environ.get("SONAR_ORACLE_URL") or DEFAULT_URL).rstrip("/")
    project_prefix = _validate_project_key(project_prefix, label="project prefix")
    scanner_digest = _image_digest(scanner_image)
    if server_image_digest is None:
        raise MetricOracleError(
            "server image digest is required; pass --server-image-digest or "
            "SONAR_ORACLE_IMAGE_DIGEST"
        )
    server_image_digest = _validate_digest(
        server_image_digest, label="server image digest"
    )
    selected = _validate_selected_cases(corpus, selected_cases)
    if token is None:
        if token_file is None:
            token_file = (
                os.environ.get("SONAR_ORACLE_TOKEN_FILE") or ".oracle/sonar/token"
            )
        token = _read_secret_file(token_file)
    api = SonarApi(url, token)
    server = discover_server_provenance(api, image_digest=server_image_digest)
    plugins = _plugin_map(server)
    cases: list[dict[str, Any]] = []
    for case in corpus["cases"]:
        if selected is not None and case["id"] not in selected:
            continue
        cases.append(
            _extract_reference_case(
                api,
                case,
                corpus_root=corpus_root,
                project_prefix=project_prefix,
                url=url,
                token=token,
                plugins=plugins,
                scanner_image=scanner_image,
                page_size=page_size,
                scan_timeout=scan_timeout,
                ce_timeout=ce_timeout,
            )
        )
    unsupported = _unsupported_reference_rows(corpus.get("unsupported", []))
    artifact = {
        "schema_version": SCHEMA_VERSION,
        "kind": REFERENCE_KIND,
        "corpus": _reference_corpus_provenance(corpus_path, corpus),
        "server_url": url,
        "server": server,
        "scanner": {"image": scanner_image, "image_digest": scanner_digest},
        "metric_keys": list(METRIC_KEYS),
        "cases": cases,
        "unsupported": unsupported,
    }
    validate_reference_artifact(artifact)
    if output_path is not None:
        write_json(output_path, artifact)
    return artifact


def _validate_reference_corpus(artifact: Mapping[str, Any]) -> None:
    corpus = artifact.get("corpus")
    if not isinstance(corpus, Mapping):
        raise ValueError("metric reference artifact lacks corpus provenance")
    if not isinstance(corpus.get("id"), str) or not corpus.get("id"):
        raise ValueError("metric reference artifact lacks corpus id")
    if corpus.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("metric reference artifact has unsupported corpus schema")
    if not isinstance(corpus.get("manifest_sha256"), str) or not re.fullmatch(
        r"[0-9a-f]{64}", corpus["manifest_sha256"]
    ):
        raise ValueError("metric reference artifact lacks manifest hash")


def _validate_reference_server(artifact: Mapping[str, Any]) -> None:
    server = artifact.get("server")
    if not isinstance(server, Mapping):
        raise ValueError("metric reference artifact lacks server provenance")
    if not isinstance(server.get("id"), str) or not server.get("id"):
        raise ValueError("metric reference artifact lacks server id")
    if not isinstance(server.get("version"), str) or not server.get("version"):
        raise ValueError("metric reference artifact lacks server version")
    if server.get("status") != "UP":
        raise ValueError("metric reference artifact server was not UP")
    if not isinstance(server.get("plugins"), list) or not server["plugins"]:
        raise ValueError("metric reference artifact lacks plugin provenance")
    _validate_digest(server.get("image_digest"), label="server image digest")


def _validate_reference_scanner(artifact: Mapping[str, Any]) -> None:
    scanner = artifact.get("scanner")
    if (
        not isinstance(scanner, Mapping)
        or not isinstance(scanner.get("image"), str)
        or not isinstance(scanner.get("image_digest"), str)
    ):
        raise ValueError("metric reference artifact lacks pinned scanner provenance")
    _validate_digest(scanner["image_digest"], label="scanner image digest")


def _validate_reference_cases(cases: list[Any]) -> None:
    ids: set[str] = set()
    for case in cases:
        if not isinstance(case, Mapping) or not isinstance(case.get("id"), str):
            raise ValueError("metric reference artifact case is malformed")
        if case["id"] in ids:
            raise ValueError("metric reference artifact repeats a case")
        ids.add(case["id"])
        status = case.get("status")
        if status not in {"COMPLETE", "INCOMPLETE", "UNVERIFIED"}:
            raise ValueError(f"metric reference case {case['id']} has invalid status")
        if status == "COMPLETE":
            if not isinstance(case.get("project"), Mapping) or not isinstance(
                case.get("files"), Mapping
            ):
                raise ValueError(
                    f"complete metric reference case {case['id']} lacks measures"
                )
            if not isinstance(case.get("duplicates"), list):
                raise ValueError(
                    f"complete metric reference case {case['id']} lacks duplicates"
                )


def validate_reference_artifact(artifact: Mapping[str, Any]) -> None:
    if (
        artifact.get("schema_version") != SCHEMA_VERSION
        or artifact.get("kind") != REFERENCE_KIND
    ):
        raise ValueError("invalid metric reference artifact schema")
    _validate_reference_corpus(artifact)
    if not isinstance(artifact.get("server_url"), str) or not artifact[
        "server_url"
    ].startswith(("http://", "https://")):
        raise ValueError("metric reference artifact lacks server URL")
    _validate_reference_server(artifact)
    _validate_reference_scanner(artifact)
    if artifact.get("metric_keys") != list(METRIC_KEYS):
        raise ValueError("metric reference artifact metric key contract changed")
    serialized = json.dumps(artifact, sort_keys=True)
    if re.search(r"(?:SONAR_TOKEN|sonar\.token|password=|secret=)", serialized, re.I):
        raise ValueError("metric reference artifact appears to contain a credential")
    cases = artifact.get("cases")
    if not isinstance(cases, list):
        raise ValueError("metric reference artifact cases must be a list")
    _validate_reference_cases(cases)


def _normal_path(path: Any) -> str | None:
    if not isinstance(path, str) or not path:
        return None
    value = path.replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    return value.lstrip("/")


def _native_project(report: Mapping[str, Any]) -> Mapping[str, Any] | None:
    project = report.get("project")
    if isinstance(project, Mapping):
        return project
    if isinstance(report.get("report"), Mapping):
        nested = report["report"].get("project")
        if isinstance(nested, Mapping):
            return nested
    return None


def _native_metric_field(metric: str) -> str | None:
    if metric == "lines":
        return "lines"
    if metric == "ncloc":
        return "code_lines"
    if metric == "comment_lines":
        return "comment_lines"
    return None


def _native_missing_duplication(
    metrics: Mapping[str, Any], metric: str
) -> tuple[Any, str]:
    if metric == DENSITY_METRIC and metrics.get("lines") in (None, 0):
        return None, "NO_DENOMINATOR"
    return None, "ABSENT"


def _native_duplication_value(
    metrics: Mapping[str, Any], duplication: Any, metric: str
) -> tuple[Any, str]:
    if not isinstance(duplication, Mapping):
        return _native_missing_duplication(metrics, metric)
    value = duplication.get(metric)
    if value is not None:
        return value, "PRESENT"
    return _native_missing_duplication(metrics, metric)


def _native_value(project: Mapping[str, Any], metric: str) -> tuple[Any, str]:
    if project.get("complete") is False:
        return None, "INCOMPLETE"
    metrics = project.get("metrics")
    if not isinstance(metrics, Mapping):
        return None, "ABSENT"
    field = _native_metric_field(metric)
    if field is not None:
        return metrics.get(field), "PRESENT" if field in metrics else "ABSENT"
    return _native_duplication_value(metrics, project.get("duplication"), metric)


def _reference_value(case: Mapping[str, Any], metric: str) -> tuple[Any, str]:
    project = case.get("project")
    if not isinstance(project, Mapping):
        return None, "UNVERIFIED"
    metrics = project.get("metrics")
    states = project.get("metric_states")
    if not isinstance(metrics, Mapping) or not isinstance(states, Mapping):
        return None, "UNVERIFIED"
    source_metric = "ncloc" if metric == "ncloc" else metric
    state = states.get(source_metric, "ABSENT")
    return metrics.get(source_metric), str(state)


def _metric_status(
    reference_value: Any, reference_state: str, native_value: Any, native_state: str
) -> str:
    if reference_state in {"UNVERIFIED", "ABSENT"}:
        return "UNVERIFIED"
    if native_state == "INCOMPLETE":
        return "UNVERIFIED"
    if reference_state == "NO_DENOMINATOR":
        return "EXACT" if native_state == "NO_DENOMINATOR" else "DIFFERENT"
    if native_state in {"ABSENT", "NO_DENOMINATOR"}:
        return "DIFFERENT"
    return "EXACT" if reference_value == native_value else "DIFFERENT"


def _file_map(project: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    rows = project.get("files")
    if isinstance(rows, Mapping):
        rows = rows.get("files")
    if not isinstance(rows, list):
        return {}
    result: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        path = _normal_path(row.get("path"))
        if path:
            result[path] = row
    return result


def _native_file_map(
    project: Mapping[str, Any] | None, reference_paths: Iterable[str]
) -> dict[str, Mapping[str, Any]]:
    """Map native files while honoring the reference metric scope."""
    if not isinstance(project, Mapping):
        return {}
    rows = project.get("files")
    if not isinstance(rows, list):
        return {}
    expected_paths = tuple(reference_paths)
    normalized_rows: list[tuple[str, Mapping[str, Any]]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        path = _normal_path(row.get("path"))
        if not path:
            continue
        # Keep every measured source/test row (including CPD-excluded source
        # rows) so missing native coverage remains visible. Only unmeasured
        # scope-inventory roots are omitted below.
        # Project inventory includes excluded/generated/vendor roots so callers
        # can explain scope decisions. They have no metric observations and are
        # not source-file metric rows.
        if (
            row.get("classification") in {"excluded", "generated", "vendor"}
            and row.get("metrics") is None
            and row.get("duplication") is None
        ):
            continue
        normalized_rows.append((path, row))
    result: dict[str, Mapping[str, Any]] = {}
    unused = list(normalized_rows)
    for reference_path in expected_paths:
        exact = [item for item in unused if item[0] == reference_path]
        candidates = exact or [
            item for item in unused if item[0].endswith(f"/{reference_path}")
        ]
        if len(candidates) == 1:
            result[reference_path] = candidates[0][1]
            unused.remove(candidates[0])
    for path, row in unused:
        result[f"native:{path}"] = row
    return result


def _compare_reference_metric(
    reference_case: Mapping[str, Any],
    native_project: Mapping[str, Any] | None,
    metric: str,
) -> dict[str, Any]:
    reference_value, reference_state = _reference_value(reference_case, metric)
    if reference_case.get("status") != "COMPLETE":
        reference_state = "UNVERIFIED"
        reference_value = None
    native_value, native_state = (
        _native_value(native_project, metric)
        if native_project is not None
        else (None, "INCOMPLETE")
    )
    status = _metric_status(
        reference_value, reference_state, native_value, native_state
    )
    reason = None
    if status == "UNVERIFIED":
        reason = (
            reference_case.get("reason")
            if reference_state == "UNVERIFIED"
            else "native project is incomplete or metric is unavailable"
        )
    return {
        "metric": metric,
        "reference": {"value": reference_value, "state": reference_state},
        "native": {"value": native_value, "state": native_state},
        "status": status,
        **({"reason": reason} if reason else {}),
    }


def _reference_file_value(
    reference_file: Mapping[str, Any] | None, metric: str
) -> tuple[Any, str]:
    ref_state = "ABSENT"
    ref_value = None
    if reference_file is not None:
        ref_values = reference_file.get("metrics")
        ref_states = reference_file.get("metric_states")
        source_metric = "ncloc" if metric == "ncloc" else metric
        if isinstance(ref_values, Mapping):
            ref_value = ref_values.get(source_metric)
        if isinstance(ref_states, Mapping):
            ref_state = str(ref_states.get(source_metric, "ABSENT"))
    return ref_value, ref_state


def _native_file_value(
    native_file: Mapping[str, Any] | None, metric: str
) -> tuple[Any, str]:
    native_state = "ABSENT"
    native_value = None
    if native_file is not None:
        native_metrics = native_file.get("metrics")
        native_source = _native_metric_field(metric)
        if native_source is not None:
            if isinstance(native_metrics, Mapping):
                native_value = native_metrics.get(native_source)
            native_state = "PRESENT" if native_value is not None else "ABSENT"
        else:
            native_duplication = native_file.get("duplication")
            if isinstance(native_duplication, Mapping):
                native_value = native_duplication.get(metric)
                native_state = "PRESENT" if native_value is not None else "ABSENT"
            if (
                metric == DENSITY_METRIC
                and native_state == "ABSENT"
                and isinstance(native_metrics, Mapping)
                and native_metrics.get("lines") in (None, 0)
            ):
                native_state = "NO_DENOMINATOR"
    return native_value, native_state


def _compare_reference_file_metric(
    reference_file: Mapping[str, Any] | None,
    native_file: Mapping[str, Any] | None,
    native_project: Mapping[str, Any] | None,
    metric: str,
) -> dict[str, Any]:
    ref_value, ref_state = _reference_file_value(reference_file, metric)
    native_value, native_state = _native_file_value(native_file, metric)
    if native_project is not None and native_project.get("complete") is False:
        native_state = "INCOMPLETE"
    if reference_file is None or native_file is None:
        row_status = "UNVERIFIED" if native_state == "INCOMPLETE" else "DIFFERENT"
    else:
        row_status = _metric_status(ref_value, ref_state, native_value, native_state)
    return {
        "metric": metric,
        "reference": {"value": ref_value, "state": ref_state},
        "native": {"value": native_value, "state": native_state},
        "status": row_status,
    }


def _compare_reference_files(
    reference_case: Mapping[str, Any], native_project: Mapping[str, Any] | None
) -> list[dict[str, Any]]:
    reference_files = (
        _file_map(reference_case.get("files", {}))
        if reference_case.get("status") == "COMPLETE"
        else {}
    )
    native_files = (
        _native_file_map(native_project, reference_files)
        if native_project is not None
        else {}
    )
    file_rows: list[dict[str, Any]] = []
    for path in sorted(set(reference_files) | set(native_files)):
        reference_file = reference_files.get(path)
        native_file = native_files.get(path)
        per_metric = [
            _compare_reference_file_metric(
                reference_file, native_file, native_project, metric
            )
            for metric in METRIC_KEYS
        ]
        file_rows.append({"path": path, "metrics": per_metric})
    return file_rows


def _comparison_overall_status(
    statuses: Sequence[str], reference_case: Mapping[str, Any], occurrence_status: str
) -> str:
    if any(status == "DIFFERENT" for status in statuses):
        return "DIFFERENT"
    if (
        any(status == "UNVERIFIED" for status in statuses)
        or reference_case.get("status") != "COMPLETE"
        or occurrence_status == "UNVERIFIED"
    ):
        return "UNVERIFIED"
    return "EXACT"


def compare_reference_case(
    reference_case: Mapping[str, Any], native_report: Mapping[str, Any]
) -> dict[str, Any]:
    """Compare one reference case, preserving explicit unavailable states."""
    case_id = reference_case.get("id")
    language = reference_case.get("language")
    native_project = _native_project(native_report)
    rows = [
        _compare_reference_metric(reference_case, native_project, metric)
        for metric in METRIC_KEYS
    ]
    file_rows = _compare_reference_files(reference_case, native_project)
    # Sonar's duplication API exposes line ranges only.  Native reports carry
    # byte ranges, so occurrence equality is deliberately not claimed.
    occurrence_status = "UNVERIFIED"
    occurrence_reason = (
        "Sonar duplication API exposes line ranges, not UTF-8 byte offsets"
    )
    statuses = [row["status"] for row in rows] + [
        metric["status"] for row in file_rows for metric in row["metrics"]
    ]
    overall = _comparison_overall_status(statuses, reference_case, occurrence_status)
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": COMPARISON_KIND,
        "case_id": case_id,
        "language": language,
        "status": overall,
        "metrics": rows,
        "files": file_rows,
        "duplication_occurrences": {
            "status": occurrence_status,
            "reason": occurrence_reason,
        },
    }


def _native_reports_by_case(
    native_reports: Mapping[str, Any]
    | Sequence[Mapping[str, Any]]
    | Mapping[str, Mapping[str, Any]],
    reference_artifact: Mapping[str, Any],
) -> dict[str, Mapping[str, Any]]:
    if isinstance(native_reports, Mapping) and isinstance(
        native_reports.get("cases"), list
    ):
        return {
            row["id"]: row["report"]
            for row in native_reports["cases"]
            if isinstance(row, Mapping)
            and isinstance(row.get("id"), str)
            and isinstance(row.get("report"), Mapping)
        }
    if isinstance(native_reports, Mapping) and isinstance(
        native_reports.get("project"), Mapping
    ):
        cases = reference_artifact.get("cases", [])
        if len(cases) == 1 and isinstance(cases[0], Mapping):
            return {cases[0]["id"]: native_reports}
    elif isinstance(native_reports, Mapping):
        return {
            key: value
            for key, value in native_reports.items()
            if isinstance(key, str) and isinstance(value, Mapping)
        }
    elif isinstance(native_reports, Sequence) and not isinstance(
        native_reports, (str, bytes)
    ):
        return {
            row["id"]: row["report"]
            for row in native_reports
            if isinstance(row, Mapping)
            and isinstance(row.get("id"), str)
            and isinstance(row.get("report"), Mapping)
        }
    return {}


def _unsupported_comparison_rows(rows: Iterable[Any]) -> list[dict[str, Any]]:
    return [
        {
            "id": row.get("id"),
            "language": row.get("language"),
            "status": "UNVERIFIED",
            "reason": row.get("reason"),
            "metrics": [
                {"metric": metric, "status": "UNVERIFIED", "reason": row.get("reason")}
                for metric in METRIC_KEYS
            ],
        }
        for row in rows
        if isinstance(row, Mapping)
    ]


def compare_reference(
    reference_artifact: Mapping[str, Any],
    native_reports: Mapping[str, Any]
    | Sequence[Mapping[str, Any]]
    | Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Compare all cases in an extracted artifact against native reports.

    ``native_reports`` may be a single Hoonarqube report (for a one-case run),
    ``{"cases": [{"id": ..., "report": ...}]}``, or a mapping of case id to
    report.  No native report is treated as an implicit zero.
    """
    validate_reference_artifact(reference_artifact)
    by_case = _native_reports_by_case(native_reports, reference_artifact)
    case_results = [
        compare_reference_case(
            reference_case,
            by_case.get(reference_case.get("id"), {"project": {"complete": False}}),
        )
        for reference_case in reference_artifact.get("cases", [])
        if isinstance(reference_case, Mapping)
    ]
    unsupported = _unsupported_comparison_rows(
        reference_artifact.get("unsupported", [])
    )
    statuses = [row["status"] for row in case_results]
    overall = (
        "DIFFERENT"
        if "DIFFERENT" in statuses
        else (
            "UNVERIFIED"
            if any(status == "UNVERIFIED" for status in statuses) or unsupported
            else "EXACT"
        )
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": COMPARISON_KIND,
        "reference_corpus": reference_artifact.get("corpus"),
        "server": reference_artifact.get("server"),
        "status": overall,
        "cases": case_results,
        "unsupported": unsupported,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="scan fixtures and extract Sonar metrics")
    run.add_argument("--corpus", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--url", default=os.environ.get("SONAR_ORACLE_URL", DEFAULT_URL))
    run.add_argument("--token-file", type=Path, default=None)
    run.add_argument("--project-prefix", default="hq45-metrics")
    run.add_argument("--scanner-image", default=DEFAULT_SCANNER_IMAGE)
    run.add_argument(
        "--server-image-digest", default=os.environ.get("SONAR_ORACLE_IMAGE_DIGEST")
    )
    run.add_argument("--case", dest="cases", action="append")
    run.add_argument("--page-size", type=int, default=3)
    run.add_argument("--scan-timeout", type=int, default=1800)
    run.add_argument("--ce-timeout", type=int, default=900)
    compare = commands.add_parser(
        "compare", help="compare reference artifact with native JSON"
    )
    compare.add_argument("--reference", type=Path, required=True)
    compare.add_argument("--native", type=Path, required=True)
    compare.add_argument("--output", type=Path, required=True)
    validate = commands.add_parser("validate", help="validate a reference artifact")
    validate.add_argument("--reference", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "run":
            extract_reference(
                args.corpus,
                args.output,
                url=args.url,
                token_file=args.token_file,
                project_prefix=args.project_prefix,
                scanner_image=args.scanner_image,
                server_image_digest=args.server_image_digest,
                selected_cases=args.cases,
                page_size=args.page_size,
                scan_timeout=args.scan_timeout,
                ce_timeout=args.ce_timeout,
            )
            return 0
        if args.command == "compare":
            reference = read_json(args.reference)
            native = read_json(args.native)
            comparison = compare_reference(reference, native)
            write_json(args.output, comparison)
            return 0 if comparison["status"] != "DIFFERENT" else 1
        validate_reference_artifact(read_json(args.reference))
        return 0
    except (
        MetricOracleError,
        OSError,
        ValueError,
        subprocess.SubprocessError,
    ) as error:
        print(_redact(str(error), None), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
