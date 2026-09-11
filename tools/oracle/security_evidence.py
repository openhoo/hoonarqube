#!/usr/bin/env python3
"""Inventory security rules and capture bounded Community sensor evidence.

This tool never treats a direct compiler oracle as a server security sensor and
never turns Community execution into Enterprise parity.  It can run synthetic
fixtures against a caller-selected Community SonarQube server when explicitly
requested with ``--execute``; otherwise it emits a complete inventory with
unexecuted/unavailable limits.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Iterable

from fetch_issues import fetch_security
from parity import (
    SECURITY_EVIDENCE_SCHEMA,
    load_infra_boundaries,
    parse_report_task,
    read_json,
    read_secret_file,
    wait_for_compute_engine as wait_for_compute_engine_helper,
    write_json_atomic,
)
from reference_provenance import file_metadata, git_provenance


REPO = Path(__file__).resolve().parents[2]
RULES = REPO / "catalog" / "rules"
RESOLUTION = REPO / "catalog" / "community-artifact-resolution.json"
INFRA = REPO / "catalog" / "infra-boundaries.json"
APPROVAL = REPO / ".oracle" / "approval.toml"
DEFAULT_OUTPUT = (
    REPO / ".oracle" / "sonar" / "results" / "security-evidence.issue44.json"
)
SCANNER_IMAGE = (
    "docker.io/sonarsource/sonar-scanner-cli@"
    "sha256:23ca0f137965d9dff2198074043fd48d386280bc5d0ccac8c8349cea4cf096a9"
)
SECURITY_TYPES = {"VULNERABILITY", "SECURITY_HOTSPOT"}
SERVER_SECURITY_TYPES = SECURITY_TYPES | {"CODE_SMELL"}
SECURITY_CLASSIFICATIONS = {"community-base", "enterprise-unverified"}
FIXTURE_DIR = REPO / "tools" / "oracle" / "fixtures" / "security"
FIXTURE_SCHEMA_VERSION = 1
CASE_NAMES = ("attack", "safe", "near_miss")
CASE_REQUIRED_FIELDS = {
    "description",
    "files",
    "sources",
    "native_args",
    "sonar_properties",
    "expected_target",
}
CASE_RESERVED_PROPERTIES = {
    "sonar.projectKey",
    "sonar.host.url",
    "sonar.token",
    "sonar.login",
    "sonar.password",
    "sonar.working.directory",
}
LANGUAGE_KEY_PREFIX = {
    "csharp": "csharpsquid",
    "javascript": "javascript",
    "typescript": "typescript",
    "python": "python",
    "go": "go",
    "rust": "rust",
}
PLUGIN_OWNER = {
    "csharp": {
        "analyzer": "SonarAnalyzer.CSharp.dll",
        "community": "SonarAnalyzer.CSharp.dll / C# server sensor",
        "community_server": "csharp",
        "enterprise_security": "securitycsharpfrontend",
    },
    "javascript": {
        "analyzer": "SonarJS analyzer",
        "community": "javascript server sensor (JavaScript/TypeScript/CSS)",
        "community_server": "javascript",
        "enterprise_security": "securityjsfrontend",
    },
    "typescript": {
        "analyzer": "SonarJS analyzer",
        "community": "javascript server sensor (JavaScript/TypeScript/CSS)",
        "community_server": "javascript",
        "enterprise_security": "securityjsfrontend",
    },
    "python": {
        "analyzer": "SonarPython analyzer",
        "community": "python server sensor",
        "community_server": "python",
        "enterprise_security": "securitypythonfrontend",
    },
    "go": {
        "analyzer": "SonarGo analyzer",
        "community": "go server sensor",
        "community_server": "go",
        "enterprise_security": "securitygofrontend",
    },
    "rust": {
        "analyzer": "SonarRust analyzer",
        "community": "rust server sensor",
        "community_server": "rust",
        "enterprise_security": "rust server sensor",
    },
}
COMMUNITY_PLUGIN_KEY = {
    "csharp": "csharp",
    "javascript": "javascript",
    "typescript": "javascript",
    "python": "python",
    "go": "go",
    "rust": "rust",
}


def _server_sensor_plugin(language: str, classification: str) -> str:
    if classification == "community-base":
        return COMMUNITY_PLUGIN_KEY[language]
    if classification == "enterprise-unverified":
        return PLUGIN_OWNER[language]["enterprise_security"]
    raise ValueError(
        f"unsupported security classification for {language}: {classification}"
    )


REFERENCE_PROFILES = {
    "csharp": {"language": "cs", "name": "Hoonarqube Oracle All cs"},
    "python": {"language": "py", "name": "Hoonarqube Oracle All py"},
    "javascript": {"language": "js", "name": "Hoonarqube Oracle All js"},
    "typescript": {"language": "ts", "name": "Hoonarqube Oracle All ts"},
    "go": {"language": "go", "name": "Hoonarqube Oracle All go"},
    "rust": {"language": "rs", "name": "Hoonarqube Oracle All rust"},
}


def _required_text(value: Any, key: str, context: str) -> str:
    field = value.get(key) if isinstance(value, dict) else None
    if not isinstance(field, str) or not field.strip():
        raise ValueError(f"{context} {key} must be a non-empty string")
    return field


def _safe_fixture_path(value: Any, *, context: str) -> str:
    """Validate a manifest path before it is materialized in a temp root."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{context} path must be a non-empty string")
    if "\x00" in value or "\\" in value:
        raise ValueError(f"{context} path must use safe POSIX separators")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError(
            f"{context} path must be relative and stay in the fixture root"
        )
    normalized = posixpath.normpath(path.as_posix())
    if normalized in {"", ".", ".."} or normalized.startswith("../"):
        raise ValueError(
            f"{context} path must be relative and stay in the fixture root"
        )
    return normalized


def _validate_unavailable_prerequisites(value: Any, *, context: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise ValueError(
            f"{context} unavailable_prerequisites must be non-empty strings"
        )
    if len(set(value)) != len(value):
        raise ValueError(f"{context} unavailable_prerequisites must be unique")
    return list(value)


def _validate_fixture_case_shape(
    value: Any, *, context: str, allow_name: bool
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{context} must be an object")
    allowed = set(CASE_REQUIRED_FIELDS) | {"unavailable_prerequisites"}
    if allow_name:
        allowed.add("name")
    missing = sorted(CASE_REQUIRED_FIELDS - set(value))
    if missing:
        raise ValueError(f"{context} missing fields: {', '.join(missing)}")
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"{context} has unknown fields: {', '.join(unknown)}")
    return value


def _normalize_fixture_files(value: dict[str, Any], *, context: str) -> dict[str, str]:
    files = value["files"]
    if not isinstance(files, dict) or not files:
        raise ValueError(f"{context} files must be a non-empty object")
    normalized: dict[str, str] = {}
    for raw_path, source in files.items():
        path = _safe_fixture_path(raw_path, context=f"{context} files")
        if path in normalized:
            raise ValueError(
                f"{context} files contain duplicate normalized path {path!r}"
            )
        if not isinstance(source, str):
            raise ValueError(f"{context} files {path!r} must contain UTF-8 text")
        if "\x00" in source:
            raise ValueError(f"{context} files {path!r} contain NUL")
        normalized[path] = source
    return dict(sorted(normalized.items()))


def _normalize_fixture_sources(
    value: dict[str, Any],
    normalized_files: dict[str, str],
    *,
    context: str,
) -> list[str]:
    sources = value["sources"]
    if not isinstance(sources, list) or not sources:
        raise ValueError(f"{context} sources must be a non-empty list")
    normalized: list[str] = []
    for source in sources:
        normalized_source = _safe_fixture_path(source, context=f"{context} sources")
        if normalized_source in normalized:
            raise ValueError(
                f"{context} sources must not contain duplicate path "
                f"{normalized_source!r}"
            )
        if normalized_source not in normalized_files and not any(
            file_path.startswith(normalized_source + "/")
            for file_path in normalized_files
        ):
            raise ValueError(
                f"{context} source {normalized_source!r} is not backed by files"
            )
        normalized.append(normalized_source)
    return normalized


def _normalize_fixture_native_args(value: dict[str, Any], *, context: str) -> list[str]:
    native_args = value["native_args"]
    if not isinstance(native_args, list) or any(
        not isinstance(argument, str) or not argument or "\x00" in argument
        for argument in native_args
    ):
        raise ValueError(f"{context} native_args must be a list of non-empty strings")
    return list(native_args)


def _normalize_fixture_properties(
    value: dict[str, Any], *, context: str
) -> dict[str, str]:
    sonar_properties = value["sonar_properties"]
    if not isinstance(sonar_properties, dict):
        raise ValueError(f"{context} sonar_properties must be an object")
    normalized: dict[str, str] = {}
    for property_name, property_value in sonar_properties.items():
        if (
            not isinstance(property_name, str)
            or not property_name.strip()
            or "\x00" in property_name
            or not isinstance(property_value, str)
            or "\x00" in property_value
        ):
            raise ValueError(f"{context} sonar_properties must map strings to strings")
        if property_name in CASE_RESERVED_PROPERTIES:
            raise ValueError(
                f"{context} sonar_properties may not override {property_name}"
            )
        normalized[property_name] = property_value
    return dict(sorted(normalized.items()))


def _validate_fixture_target(
    value: dict[str, Any], *, context: str, expected_target: bool | None
) -> bool:
    target = value["expected_target"]
    if not isinstance(target, bool):
        raise ValueError(f"{context} expected_target must be boolean")
    if expected_target is not None and target is not expected_target:
        expected_label = "true" if expected_target else "false"
        raise ValueError(
            f"{context} expected_target must be {expected_label} for this case"
        )
    return target


def _validate_fixture_case(
    value: Any,
    *,
    context: str,
    expected_target: bool | None = None,
    allow_name: bool = False,
) -> dict[str, Any]:
    case = _validate_fixture_case_shape(value, context=context, allow_name=allow_name)
    description = _required_text(case, "description", context)
    normalized_files = _normalize_fixture_files(case, context=context)
    normalized_sources = _normalize_fixture_sources(
        case, normalized_files, context=context
    )
    native_args = _normalize_fixture_native_args(case, context=context)
    sonar_properties = _normalize_fixture_properties(case, context=context)
    target = _validate_fixture_target(
        case, context=context, expected_target=expected_target
    )
    result = {
        "description": description,
        "files": normalized_files,
        "sources": normalized_sources,
        "native_args": native_args,
        "sonar_properties": sonar_properties,
        "expected_target": target,
        "unavailable_prerequisites": _validate_unavailable_prerequisites(
            case.get("unavailable_prerequisites"), context=context
        ),
    }
    if allow_name:
        result["name"] = _required_text(case, "name", context)
    return result


def _validate_manifest_header(
    path: Path, manifest: Any, language: str
) -> list[dict[str, Any]]:
    if not isinstance(manifest, dict):
        raise ValueError(f"{path} must contain a manifest object")
    required = {"schema_version", "language", "rules"}
    missing = sorted(required - set(manifest))
    if missing:
        raise ValueError(f"{path} missing fields: {', '.join(missing)}")
    allowed = required | {"unavailable_prerequisites"}
    unknown = sorted(set(manifest) - allowed)
    if unknown:
        raise ValueError(f"{path} has unknown fields: {', '.join(unknown)}")
    if manifest["schema_version"] != FIXTURE_SCHEMA_VERSION:
        raise ValueError(f"{path} schema_version must be {FIXTURE_SCHEMA_VERSION}")
    declared_language = manifest["language"]
    if (
        not isinstance(declared_language, str)
        or not declared_language.strip()
        or declared_language != language
    ):
        raise ValueError(f"{path} language must match its filename")
    rules = manifest["rules"]
    if not isinstance(rules, list):
        raise ValueError(f"{path} rules must be a list")
    if not rules:
        raise ValueError(f"{path} rules must not be empty")
    return rules


def _manifest_rule_key(
    row: dict[str, Any], *, language: str, context: str, seen_keys: set[str]
) -> str:
    key = row["key"]
    key_prefix = LANGUAGE_KEY_PREFIX.get(language)
    if (
        not isinstance(key_prefix, str)
        or not isinstance(key, str)
        or not key.strip()
        or not key.startswith(f"{key_prefix}:")
    ):
        raise ValueError(
            f"{context} key must be prefixed with {key_prefix or language}:"
        )
    if key in seen_keys:
        raise ValueError(f"duplicate security fixture key {key!r}")
    return key


def _normalize_manifest_cases(value: Any, *, context: str) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict) or set(value) != set(CASE_NAMES):
        raise ValueError(
            f"{context} cases must contain exactly attack, safe, near_miss"
        )
    return {
        case_name: _validate_fixture_case(
            value[case_name],
            context=f"{context} {case_name}",
            expected_target=case_name == "attack",
        )
        for case_name in CASE_NAMES
    }


def _normalize_manifest_flow_cases(value: Any, *, context: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError(f"{context} flow_cases must be a list")
    normalized: list[dict[str, Any]] = []
    flow_names: set[str] = set()
    for flow_index, flow_case in enumerate(value):
        flow_context = f"{context} flow_cases {flow_index}"
        normalized_flow = _validate_fixture_case(
            flow_case, context=flow_context, allow_name=True
        )
        name = normalized_flow["name"]
        if name in flow_names or name in CASE_NAMES:
            raise ValueError(f"{flow_context} name must be unique")
        flow_names.add(name)
        normalized.append(normalized_flow)
    return normalized


def _normalize_manifest_rule(
    path: Path,
    index: int,
    row: Any,
    *,
    language: str,
    seen_keys: set[str],
    manifest_sha256: str,
) -> dict[str, Any]:
    context = f"{path} rule {index}"
    if not isinstance(row, dict):
        raise ValueError(f"{context} must be an object")
    required = {"key", "rationale", "cases"}
    missing = sorted(required - set(row))
    if missing:
        raise ValueError(f"{context} missing fields: {', '.join(missing)}")
    allowed = required | {"flow_cases", "unavailable_prerequisites"}
    unknown = sorted(set(row) - allowed)
    if unknown:
        raise ValueError(f"{context} has unknown fields: {', '.join(unknown)}")
    key = _manifest_rule_key(
        row, language=language, context=context, seen_keys=seen_keys
    )
    rationale = _required_text(row, "rationale", context)
    normalized_cases = _normalize_manifest_cases(row["cases"], context=context)
    normalized_flow_cases = _normalize_manifest_flow_cases(
        row.get("flow_cases", []), context=context
    )
    seen_keys.add(key)
    return {
        "key": key,
        "rationale": rationale,
        "cases": normalized_cases,
        "flow_cases": normalized_flow_cases,
        "unavailable_prerequisites": _validate_unavailable_prerequisites(
            row.get("unavailable_prerequisites"), context=context
        ),
        "_manifest_path": str(path),
        "_manifest_sha256": manifest_sha256,
    }


def _load_security_fixture_manifest(path: Path, seen_keys: set[str]) -> dict[str, Any]:
    language = path.stem
    manifest = read_json(path)
    rules = _validate_manifest_header(path, manifest, language)
    manifest_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    normalized_rules = [
        _normalize_manifest_rule(
            path,
            index,
            row,
            language=language,
            seen_keys=seen_keys,
            manifest_sha256=manifest_sha256,
        )
        for index, row in enumerate(rules)
    ]
    return {
        "schema_version": FIXTURE_SCHEMA_VERSION,
        "language": language,
        "rules": normalized_rules,
        "unavailable_prerequisites": _validate_unavailable_prerequisites(
            manifest.get("unavailable_prerequisites"), context=str(path)
        ),
        "_path": str(path),
        "_sha256": manifest_sha256,
    }


def load_security_fixture_manifests(
    directory: str | os.PathLike[str] = FIXTURE_DIR,
) -> dict[str, dict[str, Any]]:
    """Load and strictly validate all versioned security fixture manifests."""
    root = Path(directory)
    if not root.exists():
        return {}
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"security fixture directory must be a real directory: {root}")
    manifests: dict[str, dict[str, Any]] = {}
    seen_keys: set[str] = set()
    for path in sorted(root.glob("*.json"), key=lambda item: item.name):
        if path.is_symlink() or not path.is_file():
            raise ValueError(
                f"security fixture manifest must be a regular file: {path}"
            )
        manifest = _load_security_fixture_manifest(path, seen_keys)
        manifests[manifest["language"]] = manifest
    return manifests


def load_security_fixtures(
    directory: str | os.PathLike[str] = FIXTURE_DIR,
) -> dict[str, dict[str, Any]]:
    """Return validated fixture rows keyed by their fully-qualified rule key."""
    records: dict[str, dict[str, Any]] = {}
    for manifest in load_security_fixture_manifests(directory).values():
        for row in manifest["rules"]:
            records[row["key"]] = {
                **row,
                "_manifest_language": manifest["language"],
                "_manifest_root_prerequisites": manifest["unavailable_prerequisites"],
                "_manifest_path": manifest["_path"],
                "_manifest_sha256": manifest["_sha256"],
            }
    return records


def _public_fixture_row(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {key: value for key, value in row.items() if not key.startswith("_")}


def _catalog_rules(catalog_path: Path) -> list[Any]:
    catalog = read_json(catalog_path)
    if not isinstance(catalog, dict) or not isinstance(catalog.get("rules"), list):
        raise ValueError(f"{catalog_path} must contain a rules list")
    return catalog["rules"]


def _catalog_security_row(
    catalog_path: Path,
    index: int,
    rule: Any,
    *,
    language: str,
    infra: dict[str, Any],
    manifest_records: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    context = f"{catalog_path} rule {index}"
    if not isinstance(rule, dict):
        raise ValueError(f"{context} must be an object")
    key = _required_text(rule, "external_key", context)
    rule_type = _required_text(rule, "rule_type", context)
    if rule_type not in SECURITY_TYPES:
        return None
    classification = _required_text(rule, "classification", context)
    if classification not in SECURITY_CLASSIFICATIONS:
        raise ValueError(
            f"{context} has unsupported security classification {classification!r}"
        )
    boundary = infra.get(key)
    manifest_fixture = manifest_records.get(key)
    context_limits: list[str] = []
    if boundary is not None:
        context_limits.append(boundary)
    if manifest_fixture is None:
        context_limits.append("no dedicated oracle fixture row")
    if manifest_fixture is not None:
        context_limits.extend(manifest_fixture["unavailable_prerequisites"])
        context_limits.extend(manifest_fixture.get("_manifest_root_prerequisites", []))
    server_sensor_plugin = _server_sensor_plugin(language, classification)
    owner = PLUGIN_OWNER[language]
    return {
        "key": key,
        "language": language,
        "rule_type": rule_type,
        "classification": classification,
        "implementation": {
            "catalog_row": True,
            "fixture_row": manifest_fixture is not None,
            "fixture": None,
            "fixture_manifest": _public_fixture_row(manifest_fixture),
        },
        "sensor_ownership": {
            # Keep the historical field while making the two different
            # ownership boundaries explicit.
            "direct_analyzer": owner["community"],
            "language_analyzer": owner["analyzer"],
            "community_server_plugin": owner["community_server"],
            "server_security_sensor": server_sensor_plugin,
            "enterprise_security_sensor": owner["enterprise_security"],
            "true_enterprise_sensor": classification == "enterprise-unverified",
        },
        "edition": {
            "community_reference": classification == "community-base",
            "enterprise_reference_required": classification == "enterprise-unverified",
        },
        "context": {
            # Catalog capability only; execution stays explicit in
            # community_reference.status and evidence.
            "direct_analyzer": boundary is None,
            "server_sensor": {
                "available": None,
                "observed": False,
            },
            "limits": sorted(set(context_limits)),
        },
        "community_reference": {
            "status": (
                "not-executed"
                if classification == "community-base"
                else "unsupported-enterprise-rule"
            ),
            "negative_control_claimed": False,
            "evidence": None,
            "limits": [
                (
                    "Community cannot certify Enterprise-owned rule"
                    if classification == "enterprise-unverified"
                    else "Community execution not performed for this key"
                )
            ],
        },
    }


def _validate_security_fixture_keys(
    manifest_records: dict[str, dict[str, Any]],
    catalog_security_keys: set[str],
) -> None:
    unexpected = sorted(set(manifest_records) - catalog_security_keys)
    if unexpected:
        raise ValueError(
            "security fixture keys are not catalog security rules: "
            + ", ".join(unexpected)
        )


def _catalog_security_rows() -> list[dict[str, Any]]:
    infra = load_infra_boundaries(INFRA)
    manifest_records = load_security_fixtures()
    rows: list[dict[str, Any]] = []
    catalog_security_keys: set[str] = set()
    for catalog_path in sorted(RULES.glob("*.json")):
        language = catalog_path.stem
        for index, rule in enumerate(_catalog_rules(catalog_path)):
            row = _catalog_security_row(
                catalog_path,
                index,
                rule,
                language=language,
                infra=infra,
                manifest_records=manifest_records,
            )
            if row is not None:
                rows.append(row)
                catalog_security_keys.add(row["key"])
    _validate_security_fixture_keys(manifest_records, catalog_security_keys)
    return rows


def _validate_enterprise_language_lists(raw: dict[str, Any]) -> None:
    for language, keys in raw.items():
        if language not in LANGUAGE_KEY_PREFIX:
            raise ValueError(f"enterprise resolution has unknown language {language!r}")
        if not isinstance(keys, list):
            raise ValueError(f"enterprise resolution {language} keys must be a list")


def _enterprise_csharp_keys() -> list[str]:
    resolution = read_json(RESOLUTION)
    if not isinstance(resolution, dict):
        raise ValueError("community artifact resolution must be an object")
    raw = resolution.get("enterprise_unverified_rules")
    if not isinstance(raw, dict):
        raise ValueError("enterprise resolution must contain key lists")
    _validate_enterprise_language_lists(raw)
    csharp_keys = raw.get("csharp")
    if not isinstance(csharp_keys, list):
        raise ValueError("enterprise resolution must contain csharp keys")
    if len(csharp_keys) != 17:
        raise ValueError(
            "enterprise resolution must retain exactly 17 csharp keys; "
            f"got {len(csharp_keys)}"
        )
    for index, key in enumerate(csharp_keys):
        if not isinstance(key, str) or not key.strip():
            raise ValueError(
                f"enterprise resolution csharp key {index} must be a non-empty string"
            )
    if len(set(csharp_keys)) != len(csharp_keys):
        raise ValueError("enterprise resolution csharp keys must be unique")
    return csharp_keys


def _enterprise_row(
    key: str, catalog_by_key: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    local = catalog_by_key.get(key)
    owner = PLUGIN_OWNER["csharp"]
    return {
        "key": key,
        "language": "csharp",
        "rule_type": local["rule_type"] if local else "not-in-security-inventory",
        "security_inventory_row": local is not None,
        "sensor_owner": "SonarAnalyzer.Enterprise.CSharp.dll",
        "sensor_ownership": {
            "language_analyzer": owner["analyzer"],
            "community_server_plugin": owner["community_server"],
            "enterprise_security_sensor": owner["enterprise_security"],
            "true_enterprise_sensor": True,
        },
        "edition": "enterprise",
        "reference_status": "enterprise-unverified",
        "context": {
            "local_direct_analyzer": True,
            "licensed_server_sensor": False,
            "limits": [
                "licensed Enterprise analyzer execution is unavailable",
                "Community results cannot certify this key",
            ],
        },
        "evidence": None,
    }


def _enterprise_rows(catalog_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    keys = _enterprise_csharp_keys()
    catalog_by_key = {row["key"]: row for row in catalog_rows}
    return [_enterprise_row(key, catalog_by_key) for key in keys]


def _token_from(path: Path) -> str:
    token = read_secret_file(path).strip()
    if not token:
        raise RuntimeError(f"token file is empty: {path}")
    return token


def _api_json(
    base: str, token: str, path: str, params: dict[str, str] | None = None
) -> Any:
    query = "?" + urllib.parse.urlencode(params) if params else ""
    request = urllib.request.Request(f"{base.rstrip('/')}{path}{query}")

    request.add_header(
        "Authorization",
        "Basic " + base64.b64encode(f"{token}:".encode()).decode(),
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except (OSError, urllib.error.HTTPError, json.JSONDecodeError) as error:
        raise RuntimeError(f"reference API {path} unavailable: {error}") from error


def _api_text(base: str, token: str, path: str, params: dict[str, str]) -> str:
    query = urllib.parse.urlencode(params)
    request = urllib.request.Request(f"{base.rstrip('/')}{path}?{query}")

    request.add_header(
        "Authorization",
        "Basic " + base64.b64encode(f"{token}:".encode()).decode(),
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read().decode("utf-8")
    except (OSError, urllib.error.HTTPError, UnicodeDecodeError) as error:
        raise RuntimeError(f"reference API {path} unavailable: {error}") from error


def _api_form(base: str, token: str, path: str, params: dict[str, str]) -> Any:
    request = urllib.request.Request(
        f"{base.rstrip('/')}{path}",
        data=urllib.parse.urlencode(params).encode("utf-8"),
        method="POST",
    )

    request.add_header(
        "Authorization",
        "Basic " + base64.b64encode(f"{token}:".encode()).decode(),
    )
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read().decode("utf-8")
            return json.loads(body) if body else {}
    except (OSError, urllib.error.HTTPError, json.JSONDecodeError) as error:
        raise RuntimeError(f"reference API {path} unavailable: {error}") from error


def _profile_metadata(
    base: str, token: str, language: str, required_key: str | None = None
) -> dict[str, Any]:
    profile = REFERENCE_PROFILES.get(language)
    if profile is None:
        raise RuntimeError(f"no approved Community profile is defined for {language}")
    payload = _api_json(
        base, token, "/api/qualityprofiles/search", {"language": profile["language"]}
    )
    profiles = payload.get("profiles") if isinstance(payload, dict) else None
    selected = next(
        (
            item
            for item in profiles or []
            if isinstance(item, dict) and item.get("name") == profile["name"]
        ),
        None,
    )
    if selected is None:
        raise RuntimeError(
            f"Community quality profile is unavailable: {profile['name']}"
        )
    backup = _api_text(
        base,
        token,
        "/api/qualityprofiles/backup",
        {"language": profile["language"], "qualityProfile": profile["name"]},
    )
    rule_id = (
        required_key.split(":", 1)[1]
        if isinstance(required_key, str) and ":" in required_key
        else required_key
    )
    active = (
        f"<key>{rule_id}</key>" in backup
        if isinstance(rule_id, str) and rule_id
        else None
    )
    return {
        "language": profile["language"],
        "name": profile["name"],
        "key": selected.get("key"),
        "active_rule_count": selected.get("activeRuleCount"),
        "required_rule": required_key,
        "rule_active": active,
    }


def _associate_project_profile(
    base: str, token: str, project: str, profile: dict[str, Any]
) -> dict[str, Any]:
    _api_form(
        base,
        token,
        "/api/projects/create",
        {"project": project, "name": project},
    )
    _api_form(
        base,
        token,
        "/api/qualityprofiles/add_project",
        {
            "language": profile["language"],
            "project": project,
            "qualityProfile": profile["name"],
        },
    )
    observed = _api_json(
        base,
        token,
        "/api/qualityprofiles/search",
        {"project": project, "language": profile["language"]},
    )
    profiles = observed.get("profiles") if isinstance(observed, dict) else None
    matched = next(
        (
            item
            for item in profiles or []
            if isinstance(item, dict)
            and item.get("key") == profile.get("key")
            and item.get("name") == profile.get("name")
        ),
        None,
    )
    if matched is None:
        raise RuntimeError("project/profile association was not observable")
    return {
        "project": project,
        "language": profile["language"],
        "name": profile["name"],
        "key": profile["key"],
        "association_post": "SUCCESS",
        "search_observed": True,
        "active_rule_count": matched.get("activeRuleCount"),
    }


def _server_rule_metadata(
    base: str, token: str, key: str, catalog_type: str | None = None
) -> dict[str, Any]:
    payload = _api_json(base, token, "/api/rules/show", {"key": key})
    rule = payload.get("rule") if isinstance(payload, dict) else None
    if not isinstance(rule, dict):
        raise RuntimeError(f"reference rule metadata missing for {key}")
    server_type = rule.get("type")
    if not isinstance(server_type, str) or server_type not in SERVER_SECURITY_TYPES:
        raise RuntimeError(
            f"reference rule metadata has unsupported server type for {key}: "
            f"{server_type!r}"
        )
    if catalog_type is not None and catalog_type not in SECURITY_TYPES:
        raise ValueError(
            f"catalog security type is unsupported for {key}: {catalog_type!r}"
        )
    return {
        "key": key,
        # Catalog and live types are deliberately independent.  Current
        # Community data includes catalog HOTSPOT rows served as issues.
        "catalog_type": catalog_type,
        "server_type": server_type,
        "server_status": rule.get("status"),
        "server_tags": rule.get("tags", []),
        "hotspot_endpoint": server_type == "SECURITY_HOTSPOT",
        "endpoint": (
            "/api/hotspots/search"
            if server_type == "SECURITY_HOTSPOT"
            else "/api/issues/search"
        ),
    }


def _server_metadata(base: str, token: str) -> dict[str, Any]:
    status = _api_json(base, token, "/api/system/status")
    if not isinstance(status, dict):
        raise RuntimeError("reference system status must be an object")
    result: dict[str, Any] = {
        "url": base.rstrip("/"),
        "id": status.get("id"),
        "version": status.get("version"),
        "status": status.get("status"),
        "edition": None,
        "license_valid": None,
        "plugins": [],
    }
    try:
        navigation = _api_json(base, token, "/api/navigation/global")
        if isinstance(navigation, dict):
            result["edition"] = navigation.get("edition")
    except RuntimeError as error:
        result["navigation_limit"] = str(error)
    try:
        license_result = _api_json(base, token, "/api/editions/is_valid_license")
        if isinstance(license_result, dict) and isinstance(
            license_result.get("valid"), bool
        ):
            result["license_valid"] = license_result["valid"]
    except RuntimeError as error:
        result["license_limit"] = str(error)
    try:
        plugins = _api_json(base, token, "/api/plugins/installed")
        if isinstance(plugins, dict) and isinstance(plugins.get("plugins"), list):
            result["plugins"] = [
                {
                    "key": plugin.get("key"),
                    "version": plugin.get("version"),
                    "edition_bundled": plugin.get("editionBundled"),
                }
                for plugin in plugins["plugins"]
                if isinstance(plugin, dict)
            ]
    except RuntimeError as error:
        result["plugin_limit"] = str(error)
    return result


def _case_language(key: str) -> str:
    prefix = key.split(":", 1)[0]
    for language, key_prefix in LANGUAGE_KEY_PREFIX.items():
        if prefix == key_prefix:
            return language
    return prefix


def _community_sensor_gate(server: dict[str, Any], language: str) -> tuple[bool, str]:
    if server.get("status") != "UP":
        return False, f"Community server status is not UP: {server.get('status')!r}"
    edition = server.get("edition")
    if not isinstance(edition, str) or edition.lower() != "community":
        return False, "Community server edition was not confirmed"
    plugins = server.get("plugins")
    plugin_key = COMMUNITY_PLUGIN_KEY.get(language)
    if not isinstance(plugins, list) or not plugin_key:
        return False, f"Community sensor metadata is unavailable for {language}"
    observed_keys = {
        plugin.get("key")
        for plugin in plugins
        if isinstance(plugin, dict) and isinstance(plugin.get("key"), str)
    }
    if plugin_key not in observed_keys:
        return False, f"Community sensor plugin {plugin_key} was not observed"
    return True, ""


def _repo_digest(value: str) -> tuple[str, str] | None:
    repository, separator, digest = value.partition("@")
    if not separator or not repository or not digest:
        return None
    return repository, digest


def _verify_scanner_image() -> tuple[bool, str]:
    """Require the exact pinned repository@digest to be locally inspectable."""
    expected = _repo_digest(SCANNER_IMAGE)
    if expected is None:
        return False, "configured scanner image is not repository@digest"
    try:
        inspected = subprocess.run(
            [
                "podman",
                "image",
                "inspect",
                "--format",
                "{{json .RepoDigests}}",
                SCANNER_IMAGE,
            ],
            cwd=REPO,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return False, f"cannot inspect pinned scanner image: {error}"
    if inspected.returncode != 0:
        return False, "local scanner image digest does not match pinned digest"
    raw = inspected.stdout.strip()
    try:
        repo_digests = json.loads(raw) if raw else []
    except json.JSONDecodeError:
        repo_digests = [line.strip() for line in raw.splitlines() if line.strip()]
    if isinstance(repo_digests, str):
        repo_digests = [repo_digests]
    if not isinstance(repo_digests, list) or any(
        not isinstance(item, str) for item in repo_digests
    ):
        return False, "local scanner image inspection did not return repository digests"
    if any(_repo_digest(item) == expected for item in repo_digests):
        return True, SCANNER_IMAGE
    return False, "local scanner image digest does not match pinned digest"


def _wait_for_compute_engine(
    base: str, token: str, report_task: str, project: str
) -> dict[str, Any]:
    task = parse_report_task(report_task, expected_project=project)

    def fetch_status(task_id: str) -> str | None:
        payload = _api_json(base, token, "/api/ce/task", {"id": task_id})
        task_data = payload.get("task") if isinstance(payload, dict) else None
        return task_data.get("status") if isinstance(task_data, dict) else None

    status = wait_for_compute_engine_helper(
        task["ceTaskId"],
        fetch_status,
        lambda: time.sleep(2),
        attempts=150,
    )
    if status != "SUCCESS":
        raise RuntimeError(f"Sonar Compute Engine task {status}")
    return {"id": task["ceTaskId"], "status": status}


def _case_outcome(
    key: str,
    case_name: str,
    *,
    expected_target: bool | None = None,
    comparison: str | None = None,
    finding_count: int | None = None,
    target_rules: list[str] | None = None,
) -> dict[str, Any]:
    detected = case_name == "attack" if expected_target is None else expected_target
    expected_contract = (
        "at-least-one-target-finding" if detected else "zero-target-findings"
    )
    observed = (
        None
        if finding_count is None
        else {
            "rule_key": key,
            "detected": finding_count > 0,
            "finding_count": finding_count,
            "target_rules": sorted(target_rules or []),
        }
    )
    return {
        "status": (
            "UNVERIFIED"
            if comparison is None
            else "PASS"
            if comparison == "EXPECTED_MATCH"
            else "FAIL"
        ),
        "rule_key": key,
        "expected": {
            "rule_key": key,
            "detected": detected,
            "finding_count": (
                {"minimum": 1, "maximum": None}
                if detected
                else {"minimum": 0, "maximum": 0}
            ),
        },
        "observed": observed,
        "expected_contract": expected_contract,
        "comparison": comparison,
        "observed_finding_count": finding_count,
        "observed_target_rules": sorted(target_rules or []),
        "negative_control_claimed": False,
    }


_MISSING = object()


def _case_result(
    common: dict[str, Any],
    status: str,
    limits: list[str],
    *,
    project: str | None = None,
    scanner_digest: str | None = None,
    compute_engine: Any = _MISSING,
    evidence: Any = None,
) -> dict[str, Any]:
    inherited_limits = common.get("limits", [])
    all_limits = [
        value
        for value in [*inherited_limits, *limits]
        if isinstance(value, str) and value
    ]
    result = {
        **common,
        "status": status,
        "limits": sorted(set(all_limits)),
        "project": project,
        "scanner_digest": scanner_digest,
    }
    if compute_engine is not _MISSING:
        result["compute_engine"] = compute_engine
    result["evidence"] = evidence
    return result


def _fixture_case(
    fixture: dict[str, Any], key: str, case_name: str
) -> tuple[dict[str, Any] | None, str | None]:
    if case_name in CASE_NAMES:
        case = fixture.get("cases", {}).get(case_name)
    else:
        case = next(
            (
                candidate
                for candidate in fixture.get("flow_cases", [])
                if isinstance(candidate, dict) and candidate.get("name") == case_name
            ),
            None,
        )
    if not isinstance(case, dict):
        return None, f"security fixture case is missing: {key}/{case_name}"
    return case, None


def _fixture_source_identity(
    fixture: dict[str, Any],
    case: dict[str, Any],
    *,
    key: str,
    case_name: str,
) -> dict[str, Any]:
    files = case["files"]
    rows: list[dict[str, Any]] = []
    digest = hashlib.sha256()
    for path, source in sorted(files.items()):
        data = source.encode("utf-8")
        source_digest = hashlib.sha256(data).hexdigest()
        rows.append({"path": path, "size": len(data), "sha256": source_digest})
        path_bytes = path.encode("utf-8")
        digest.update(len(path_bytes).to_bytes(8, "big"))
        digest.update(path_bytes)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return {
        "kind": "fixture-manifest",
        "key": key,
        "case": case_name,
        "sources": list(case["sources"]),
        "files": rows,
        "sha256": digest.hexdigest(),
        "config": {
            "native_args": list(case["native_args"]),
            "sonar_properties": dict(case["sonar_properties"]),
        },
        "manifest": fixture["_manifest_path"],
        "manifest_sha256": fixture["_manifest_sha256"],
    }


def _fixture_case_names(fixture: dict[str, Any] | None) -> list[str]:
    if fixture is None:
        return list(CASE_NAMES)
    names = list(CASE_NAMES)
    names.extend(
        flow["name"]
        for flow in fixture.get("flow_cases", [])
        if isinstance(flow, dict) and isinstance(flow.get("name"), str)
    )
    return names


def _case_common_for_case(
    key: str,
    case_name: str,
    rule_metadata: dict[str, Any],
    fixture: dict[str, Any] | None,
    case: dict[str, Any] | None,
    limit: str | None,
    *,
    defer_outcome: bool = False,
) -> dict[str, Any]:
    case_values = case if isinstance(case, dict) else {}
    language = _case_language(key)
    server_type = rule_metadata.get("server_type")
    hotspot_endpoint = server_type == "SECURITY_HOTSPOT"
    common: dict[str, Any] = {
        "key": key,
        "case": case_name,
        "sensor": {
            "rule_key": key,
            "catalog_kind": rule_metadata.get("catalog_type"),
            "kind": server_type,
            "edition": "community",
            "endpoint": (
                "/api/hotspots/search" if hotspot_endpoint else "/api/issues/search"
            ),
        },
        "rule_metadata": rule_metadata,
        "scanner_image": (
            SCANNER_IMAGE if language != "csharp" else "csharp-owning-sonar-scanner"
        ),
        "execution": {
            "language": language,
            "working_directory": "materialized-case-root",
            "native_args": list(case_values.get("native_args", [])),
            "sonar_properties": dict(case_values.get("sonar_properties", {})),
            "native_replay": {
                "status": "NOT_EXECUTED",
                "cwd": "materialized-case-root",
                "comparison": "DEFERRED_TO_CALLER",
            },
        },
    }
    case_limits: list[str] = []
    if limit is not None:
        case_limits.append(limit)
    if case is not None:
        common["expected_target"] = case["expected_target"]
        common["description"] = case["description"]
        common["source"] = _fixture_source_identity(
            fixture, case, key=key, case_name=case_name
        )
        if not defer_outcome:
            common["outcome"] = _case_outcome(
                key, case_name, expected_target=case["expected_target"]
            )
        case_limits.extend(case.get("unavailable_prerequisites", []))
        if fixture is not None:
            case_limits.extend(fixture.get("_manifest_root_prerequisites", []))
            case_limits.extend(fixture.get("unavailable_prerequisites", []))
    else:
        common["outcome"] = _case_outcome(key, case_name)
    if case_limits:
        common["limits"] = sorted(
            {value for value in case_limits if isinstance(value, str) and value}
        )
    return common


def _case_common(
    key: str,
    case_name: str,
    rule_metadata: dict[str, Any],
    fixture: dict[str, Any] | None,
) -> dict[str, Any]:
    if fixture is None:
        case = None
        limit = f"security fixture manifest is unavailable: {key}/{case_name}"
    else:
        case, limit = _fixture_case(fixture, key, case_name)
    return _case_common_for_case(key, case_name, rule_metadata, fixture, case, limit)


def _unavailable_case_results(
    key: str,
    rule_metadata: dict[str, Any],
    fixture: dict[str, Any] | None,
    reason: str,
) -> list[dict[str, Any]]:
    return [
        _case_result(
            _case_common(key, case_name, rule_metadata, fixture),
            "unavailable",
            [reason],
        )
        for case_name in _fixture_case_names(fixture)
    ]


def _prepare_reference_profile(
    base: str,
    token: str,
    project: str,
    rule_metadata: dict[str, Any],
) -> tuple[dict[str, Any] | None, str | None]:
    profile = rule_metadata.get("profile")
    key = rule_metadata.get("key")
    active = profile.get("rule_active") if isinstance(profile, dict) else None
    if active is not True:
        return (
            None,
            f"{key or 'target rule'} is not proven active in the selected "
            "Community profile",
        )
    try:
        association = _associate_project_profile(base, token, project, profile)
    except (OSError, RuntimeError, ValueError) as error:
        return None, f"project/profile association failed: {error}"
    return {**rule_metadata, "profile_association": association}, None


def _materialize_fixture_files(
    root: Path, case: dict[str, Any]
) -> tuple[list[str], dict[str, bytes]]:
    files = case.get("files")
    sources = case.get("sources")
    if not isinstance(files, dict) or not files:
        raise ValueError("security fixture case files must be a non-empty object")
    if not isinstance(sources, list) or not sources:
        raise ValueError("security fixture case sources must be a non-empty list")
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o755)
    materialized: dict[str, bytes] = {}
    for raw_path, source in files.items():
        path = _safe_fixture_path(raw_path, context="security fixture case files")
        if not isinstance(source, str):
            raise ValueError(f"security fixture case file {path!r} is not text")
        destination = root / path
        try:
            destination.resolve().relative_to(root.resolve())
        except ValueError as error:
            raise ValueError(
                f"security fixture case file escapes root: {path}"
            ) from error
        destination.parent.mkdir(parents=True, exist_ok=True)
        data = source.encode("utf-8")
        destination.write_bytes(data)
        destination.chmod(0o644)
        materialized[path] = data
    normalized_sources: list[str] = []
    for raw_source in sources:
        source = _safe_fixture_path(raw_source, context="security fixture case sources")
        if source not in materialized and not any(
            path.startswith(source + "/") for path in materialized
        ):
            raise ValueError(f"security fixture source is not materialized: {source}")
        normalized_sources.append(source)
    return normalized_sources, materialized


def _scanner_properties(case: dict[str, Any], sources: list[str]) -> dict[str, str]:
    properties = case.get("sonar_properties")
    if not isinstance(properties, dict):
        raise ValueError("security fixture case sonar_properties must be an object")
    normalized = {
        str(name): str(value)
        for name, value in properties.items()
        if isinstance(name, str) and isinstance(value, str)
    }
    source_value = ",".join(sources)
    configured_sources = normalized.get("sonar.sources")
    if configured_sources is not None and configured_sources != source_value:
        raise ValueError(
            "security fixture sonar.sources must match the case sources array"
        )
    normalized.setdefault("sonar.sources", source_value)
    return dict(sorted(normalized.items()))


def _native_args(case: dict[str, Any]) -> list[str]:
    values = case.get("native_args")
    if not isinstance(values, list):
        raise ValueError("security fixture case native_args must be a list")
    result: list[str] = []
    for index, value in enumerate(values):
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ValueError(
                f"security fixture native_args[{index}] must be a non-empty string"
            )
        result.append(value)
    return result


def _read_report_task(path: Path) -> str | None:
    if not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None


def _csharp_auth_arg(token: str, server_version: str | None) -> str:
    auth_name = (
        "sonar.login"
        if isinstance(server_version, str) and server_version.startswith("9.")
        else "sonar.token"
    )
    return f"/d:{auth_name}={token}"


def _run_csharp_begin(
    parity_suite: Any,
    scanner_path: Any,
    project: str,
    root: Path,
    case: dict[str, Any],
    auth_arg: str,
) -> Any:
    case_properties = case.get("sonar_properties", {})
    if not isinstance(case_properties, dict):
        raise ValueError("C# sonar_properties must be an object")
    if not case_properties:
        return parity_suite._native_begin(project, scanner_path, root, auth_arg)
    begin_command = parity_suite.csharp_begin_command(
        scanner_path, project, root, auth_arg
    )
    begin_command.extend(
        f"/d:{name}={value}" for name, value in sorted(case_properties.items())
    )
    return subprocess.run(
        begin_command,
        cwd=root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=900,
        check=False,
    )


def _csharp_solution(root: Path, work: Path, generate_solution: Any) -> tuple[Any, int]:
    project_files = sorted(root.glob("*.sln")) + sorted(root.glob("*.csproj"))
    if project_files:
        solution = project_files[0]
        fixture_count = len([path for path in root.rglob("*.cs") if path.is_file()])
    else:
        solution, fixture_count = generate_solution(root, work)
    return solution, fixture_count


def _csharp_scan_result(
    build: Any,
    end: Any,
    report_task: str | None,
    fixture_count: int,
    scanner_path: Any,
) -> tuple[int | None, str | None, str | None, str | None]:
    scanner = str(scanner_path)
    if end is None:
        result = (
            build.returncode if build is not None else None,
            report_task,
            "C# owning Sonar scanner end timed out",
            scanner,
        )
    elif end.returncode != 0:
        result = (
            build.returncode if build is not None else end.returncode,
            report_task,
            f"C# owning Sonar scanner end exited {end.returncode}",
            scanner,
        )
    elif build is None:
        result = (None, report_task, "C# native build did not run", scanner)
    elif build.returncode != 0:
        result = (
            build.returncode,
            report_task,
            f"C# native build exited {build.returncode}",
            scanner,
        )
    elif report_task is None:
        result = (
            build.returncode,
            None,
            "C# owning Sonar scanner completed without report-task.txt",
            scanner,
        )
    elif fixture_count < 1:
        result = (
            build.returncode,
            report_task,
            "C# owning Sonar scanner had no source fixtures",
            scanner,
        )
    else:
        result = build.returncode, report_task, None, scanner
    return result


def _execute_csharp_scan(
    parity_suite: Any,
    generate_solution: Any,
    scanner_path: Any,
    token: str,
    project: str,
    root: Path,
    work: Path,
    case: dict[str, Any],
    server_version: str | None,
) -> tuple[int | None, str | None, str | None, str | None]:
    auth_arg = _csharp_auth_arg(token, server_version)
    begin = _run_csharp_begin(parity_suite, scanner_path, project, root, case, auth_arg)
    if begin is None:
        return None, None, "C# owning Sonar scanner begin failed", str(scanner_path)
    if begin.returncode != 0:
        return (
            begin.returncode,
            _read_report_task(root / ".sonarqube/out/.sonar/report-task.txt"),
            f"C# owning Sonar scanner begin exited {begin.returncode}",
            str(scanner_path),
        )
    solution, fixture_count = _csharp_solution(root, work, generate_solution)
    build, end = parity_suite._native_build_and_end(
        project,
        scanner_path,
        root,
        solution,
        auth_arg,
    )
    report_task = _read_report_task(root / ".sonarqube/out/.sonar/report-task.txt")
    return _csharp_scan_result(build, end, report_task, fixture_count, scanner_path)


def _run_csharp_scanner(
    base: str,
    token: str,
    project: str,
    root: Path,
    work: Path,
    case: dict[str, Any],
    server_version: str | None,
) -> tuple[int | None, str | None, str | None, str | None]:
    """Run the owning Sonar C# scanner around a real build, never Roslyn-only."""
    try:
        import parity_suite
        from csharp_oracle import generate_solution

        scanner_path = parity_suite.csharp_scanner_path()
        if scanner_path is None:
            return (
                None,
                None,
                "Community C# owning Sonar scanner path is unavailable",
                None,
            )
        old_url = parity_suite.SONAR_URL
        parity_suite.SONAR_URL = base.rstrip("/")
        try:
            return _execute_csharp_scan(
                parity_suite,
                generate_solution,
                scanner_path,
                token,
                project,
                root,
                work,
                case,
                server_version,
            )
        finally:
            parity_suite.SONAR_URL = old_url
    except (ImportError, OSError, RuntimeError, TypeError, ValueError) as error:
        return None, None, f"C# owning Sonar scanner unavailable: {error}", None


def _run_scanner(
    base: str,
    token: str,
    project: str,
    language: str,
    case: dict[str, Any],
    *,
    server_version: str | None = None,
) -> tuple[int | None, str | None, str | None]:
    with (
        tempfile.TemporaryDirectory(prefix=f"issue44-{language}-") as directory,
        tempfile.TemporaryDirectory(prefix="issue44-env-") as env_directory,
        tempfile.TemporaryDirectory(prefix="issue44-work-") as work_directory,
    ):
        root = Path(directory)
        work = Path(work_directory)
        sources, _ = _materialize_fixture_files(root, case)
        properties = _scanner_properties(case, sources)
        if language == "csharp":
            return_code, report_task, limit, _ = _run_csharp_scanner(
                base,
                token,
                project,
                root,
                work,
                case,
                server_version,
            )
            return return_code, report_task, limit
        env_file = Path(env_directory) / "scanner.env"
        env_file.write_text(
            f"SONAR_HOST_URL={base}\nSONAR_TOKEN={token}\n", encoding="utf-8"
        )
        env_file.chmod(0o600)
        command = [
            "podman",
            "run",
            "--rm",
            "--pull=never",
            "--userns=keep-id",
            "--network",
            "host",
            "--env-file",
            str(env_file),
            "-v",
            f"{root}:/usr/src:Z",
            "-v",
            f"{work}:/tmp/sonar:Z",
            SCANNER_IMAGE,
            f"-Dsonar.projectKey={project}",
            f"-Dsonar.host.url={base}",
            "-Dsonar.working.directory=/tmp/sonar",
        ]
        command.extend(f"-D{name}={value}" for name, value in properties.items())
        try:
            completed = subprocess.run(
                command,
                cwd=root,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=900,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            return None, None, f"Community scanner execution failed: {error}"
        return (
            completed.returncode,
            _read_report_task(work / "report-task.txt"),
            None,
        )


def _scanner_case_result(
    common: dict[str, Any],
    return_code: int | None,
    report_task_text: str | None,
    scanner_limit: str | None,
    project: str,
    image_identity: str,
) -> dict[str, Any] | None:
    if scanner_limit is not None:
        return _case_result(
            common,
            "unavailable",
            [scanner_limit],
            project=project,
            scanner_digest=image_identity,
        )
    if return_code is None or return_code != 0:
        return _case_result(
            common,
            "unavailable",
            [
                "Community scanner execution failed",
                f"scanner exit code {return_code}",
            ],
            project=project,
            scanner_digest=image_identity,
        )
    if report_task_text is None:
        return _case_result(
            common,
            "incomplete",
            [
                "scanner completed without report-task.txt; Compute Engine status is unknown"
            ],
            project=project,
            scanner_digest=image_identity,
        )
    return None


def _fetch_case_evidence(
    base: str,
    token: str,
    project: str,
    key: str,
    hotspot_endpoint: bool,
) -> tuple[Any, str | None]:
    try:
        # fetch_security intentionally certifies Community only; the server
        # edition is recorded separately and never supplied as Enterprise.
        import fetch_issues

        fetch_issues.BASE = base.rstrip("/")
        previous_token = os.environ.get("SONAR_ORACLE_TOKEN")
        os.environ["SONAR_ORACLE_TOKEN"] = token
        try:
            return (
                fetch_security(
                    project,
                    hotspot=hotspot_endpoint,
                    edition="community",
                    rule=key,
                ),
                None,
            )
        finally:
            if previous_token is None:
                os.environ.pop("SONAR_ORACLE_TOKEN", None)
            else:
                os.environ["SONAR_ORACLE_TOKEN"] = previous_token
    except (OSError, RuntimeError, ValueError) as error:
        return None, f"scanner completed but security evidence was incomplete: {error}"


def _unexpected_finding_rules(findings: list[Any], key: str) -> list[str]:
    unexpected_rules: list[str] = []
    for index, item in enumerate(findings):
        if not isinstance(item, dict):
            unexpected_rules.append(f"finding[{index}]:not-an-object")
        elif item.get("rule") != key:
            unexpected_rules.append(f"finding[{index}]:{item.get('rule')!r}")
    return unexpected_rules


def _capture_case_evidence(
    common: dict[str, Any],
    base: str,
    token: str,
    key: str,
    case_name: str,
    project: str,
    image_identity: str,
    hotspot_endpoint: bool,
    compute_engine: dict[str, Any],
) -> dict[str, Any]:
    evidence, evidence_limit = _fetch_case_evidence(
        base, token, project, key, hotspot_endpoint
    )
    if evidence_limit is not None:
        return _case_result(
            common,
            "incomplete",
            [evidence_limit],
            project=project,
            scanner_digest=image_identity,
            compute_engine=compute_engine,
        )
    if not isinstance(evidence, dict):
        return _case_result(
            common,
            "incomplete",
            ["security evidence response is not an object"],
            project=project,
            scanner_digest=image_identity,
            compute_engine=compute_engine,
        )
    findings = evidence.get("findings", [])
    if not isinstance(findings, list):
        return _case_result(
            common,
            "incomplete",
            ["security evidence findings is not a list"],
            project=project,
            scanner_digest=image_identity,
            compute_engine=compute_engine,
            evidence=evidence,
        )
    unexpected_rules = _unexpected_finding_rules(findings, key)
    if unexpected_rules:
        return _case_result(
            common,
            "incomplete",
            [f"target rule filter returned unexpected rules: {unexpected_rules}"],
            project=project,
            scanner_digest=image_identity,
            compute_engine=compute_engine,
            evidence=evidence,
        )
    expected_target = common.get("expected_target")
    if not isinstance(expected_target, bool):
        expected_target = case_name == "attack"
    finding_count = len(findings)
    detected = finding_count > 0
    comparison = (
        "EXPECTED_MATCH"
        if detected is expected_target
        else "UNEXPECTED_MISS"
        if expected_target
        else "UNEXPECTED_FINDING"
    )
    target_rules = sorted(
        {
            item.get("rule")
            for item in findings
            if isinstance(item, dict) and isinstance(item.get("rule"), str)
        }
    )
    outcome = _case_outcome(
        key,
        case_name,
        expected_target=expected_target,
        comparison=comparison,
        finding_count=finding_count,
        target_rules=target_rules,
    )
    return {
        **common,
        "status": "captured",
        "negative_control_claimed": (
            not expected_target and comparison == "EXPECTED_MATCH"
        ),
        "outcome": outcome,
        "limits": list(evidence.get("limits", [])),
        "project": project,
        "scanner_digest": image_identity,
        "compute_engine": compute_engine,
        "evidence": evidence,
    }


def _prepare_reference_case(
    base: str,
    token: str,
    project: str,
    language: str,
    key: str,
    rule_metadata: dict[str, Any],
    common: dict[str, Any],
) -> dict[str, Any] | None:
    try:
        if not isinstance(rule_metadata.get("profile"), dict):
            rule_metadata["profile"] = _profile_metadata(
                base, token, language, required_key=key
            )
        server_context = rule_metadata.get("server")
        if isinstance(server_context, dict):
            sensor_available, sensor_limit = _community_sensor_gate(
                server_context, language
            )
        else:
            sensor_available, sensor_limit = True, ""
    except (OSError, RuntimeError, ValueError) as error:
        return _case_result(common, "incomplete", [f"reference setup failed: {error}"])
    if not sensor_available:
        return _case_result(common, "unavailable", [sensor_limit])
    case_metadata, profile_limit = _prepare_reference_profile(
        base, token, project, rule_metadata
    )
    if profile_limit is not None:
        return _case_result(
            common,
            "incomplete",
            [profile_limit],
            project=project,
            scanner_digest=common["scanner_image"],
        )
    common["profile_association"] = case_metadata["profile_association"]
    common["rule_metadata"] = case_metadata
    return None


def _run_reference_scanner(
    base: str,
    token: str,
    key: str,
    case_name: str,
    language: str,
    case: dict[str, Any],
    common: dict[str, Any],
    hotspot_endpoint: bool,
    project: str,
    server_version: str | None,
) -> dict[str, Any]:
    image_identity = common["scanner_image"]
    try:
        return_code, report_task_text, scanner_limit = _run_scanner(
            base,
            token,
            project,
            language,
            case,
            server_version=server_version,
        )
    except (OSError, RuntimeError, ValueError) as error:
        return _case_result(
            common,
            "incomplete",
            [f"scanner execution failed: {error}"],
            project=project,
            scanner_digest=image_identity,
        )
    scanner_result = _scanner_case_result(
        common,
        return_code,
        report_task_text,
        scanner_limit,
        project,
        image_identity,
    )
    if scanner_result is not None:
        return scanner_result
    try:
        compute_engine = _wait_for_compute_engine(
            base, token, report_task_text, project
        )
    except (OSError, RuntimeError, ValueError) as error:
        return _case_result(
            common,
            "incomplete",
            [f"Compute Engine evidence unavailable: {error}"],
            project=project,
            scanner_digest=image_identity,
        )
    return _capture_case_evidence(
        common,
        base,
        token,
        key,
        case_name,
        project,
        image_identity,
        hotspot_endpoint,
        compute_engine,
    )


def _run_reference_case(
    base: str,
    token: str,
    key: str,
    case_name: str,
    rule_metadata: dict[str, Any],
    fixture: dict[str, Any],
) -> dict[str, Any]:
    observed_type = rule_metadata.get("server_type")
    if observed_type not in SERVER_SECURITY_TYPES:
        common = _case_common(key, case_name, rule_metadata, fixture)
        return _case_result(
            common,
            "incomplete",
            [f"unsupported live server security type: {observed_type!r}"],
        )
    hotspot_endpoint = observed_type == "SECURITY_HOTSPOT"
    language = _case_language(key)
    case, source_limit = _fixture_case(fixture, key, case_name)
    common = _case_common_for_case(
        key,
        case_name,
        rule_metadata,
        fixture,
        case,
        source_limit,
        defer_outcome=True,
    )
    if case is not None and common.get("limits"):
        return _case_result(common, "unavailable", common["limits"])
    common["outcome"] = _case_outcome(
        key, case_name, expected_target=common.get("expected_target")
    )
    if source_limit is not None or case is None:
        return _case_result(
            common,
            "unavailable",
            [source_limit or "security fixture case is unavailable"],
        )
    if language != "csharp":
        image_available, image_limit = _verify_scanner_image()
        if not image_available:
            return _case_result(common, "unavailable", [image_limit])
    project = (
        f"hoonarqube-issue44-{language}-{case_name.replace('_', '-')}-"
        f"{uuid.uuid4().hex[:12]}"
    )
    common["execution"]["project_key"] = project
    common["execution"]["scanner"] = {
        "kind": (
            "csharp-owning-sonar-scanner"
            if language == "csharp"
            else "community-scanner-cli"
        ),
        "image": common["scanner_image"],
        "receives": "sonar_properties-only",
    }
    setup_result = _prepare_reference_case(
        base, token, project, language, key, rule_metadata, common
    )
    if setup_result is not None:
        return setup_result
    return _run_reference_scanner(
        base,
        token,
        key,
        case_name,
        language,
        case,
        common,
        hotspot_endpoint,
        project,
        rule_metadata.get("server_version"),
    )


def _apply_server_context(rows: list[dict[str, Any]], server: dict[str, Any]) -> None:
    plugin_keys = {
        plugin.get("key")
        for plugin in server.get("plugins", [])
        if isinstance(plugin, dict) and isinstance(plugin.get("key"), str)
    }
    server_up = server.get("status") == "UP"
    observed_edition = server.get("edition")
    edition_known = isinstance(observed_edition, str) and bool(observed_edition)
    for row in rows:
        owner_key = row["sensor_ownership"]["server_security_sensor"]
        plugin_observed = owner_key in plugin_keys
        sensor = row["context"]["server_sensor"]
        sensor["observed"] = plugin_observed
        sensor["owner_plugin"] = owner_key
        sensor["available"] = (
            bool(server_up and plugin_observed) if server.get("plugins") else None
        )
        sensor["server_status"] = server.get("status")
        sensor["observed_edition"] = observed_edition
        row["edition"]["observed"] = observed_edition
        row["edition"]["community_reference_available"] = (
            bool(server_up and observed_edition.lower() == "community")
            if edition_known
            else None
        )
        if not plugin_observed:
            row["context"]["limits"].append(
                f"server plugin {owner_key} was not observed in captured plugin metadata"
            )
        if not edition_known:
            row["context"]["limits"].append(
                "server edition was not observed; Community availability remains unknown"
            )


def _execution_language_keys(
    selected_language: str,
    rows: list[dict[str, Any]],
    fixtures: dict[str, dict[str, Any]],
) -> list[str]:
    keys = sorted(row["key"] for row in rows if row["language"] == selected_language)
    missing = [key for key in keys if key not in fixtures]
    if missing:
        raise ValueError(
            "selected security language has no validated fixture manifest for: "
            + ", ".join(missing)
        )
    return keys


def _matching_execution_language(selector: str) -> str | None:
    return next(
        (
            name
            for name, prefix in LANGUAGE_KEY_PREFIX.items()
            if selector in {name, prefix}
        ),
        None,
    )


def _select_catalog_execution_key(
    selector: str,
    language: str | None,
    catalog_by_key: dict[str, dict[str, Any]],
) -> str:
    row_language = catalog_by_key[selector]["language"]
    if language is not None and row_language != language:
        raise ValueError(
            f"security key {selector} does not belong to selected language {language}"
        )
    return selector


def _select_language_execution_keys(
    selector: str,
    language: str | None,
    rows: list[dict[str, Any]],
    fixtures: dict[str, dict[str, Any]],
) -> list[str]:
    matching_language = _matching_execution_language(selector)
    if matching_language is None:
        raise ValueError(f"unknown security execution selector: {selector}")
    if language is not None and matching_language != language:
        raise ValueError(
            f"security selector {selector} does not belong to selected language "
            f"{language}"
        )
    return _execution_language_keys(matching_language, rows, fixtures)


def _validate_selected_execution_keys(
    selected: set[str], fixtures: dict[str, dict[str, Any]]
) -> None:
    missing = sorted(key for key in selected if key not in fixtures)
    if missing:
        raise ValueError(
            "selected security keys have no validated fixture manifest: "
            + ", ".join(missing)
        )


def _resolve_execution_keys(
    execute: Iterable[str],
    language: str | None,
    rows: list[dict[str, Any]],
    fixtures: dict[str, dict[str, Any]],
) -> list[str]:
    catalog_by_key = {row["key"]: row for row in rows}
    selectors = list(execute)
    if language is not None and language not in LANGUAGE_KEY_PREFIX:
        raise ValueError(f"unsupported security execution language: {language}")
    selected: set[str] = set()
    for selector in selectors:
        if selector in catalog_by_key:
            selected.add(
                _select_catalog_execution_key(selector, language, catalog_by_key)
            )
        else:
            selected.update(
                _select_language_execution_keys(selector, language, rows, fixtures)
            )
    if language is not None and not selectors:
        selected.update(_execution_language_keys(language, rows, fixtures))
    _validate_selected_execution_keys(selected, fixtures)
    return sorted(selected)


def _input_file_metadata(path: Path) -> dict[str, Any]:
    try:
        return file_metadata(path, root=REPO)
    except (OSError, ValueError) as error:
        return {
            "path": str(path),
            "available": False,
            "error": str(error),
        }


def _input_file_metadata_rows(paths: Iterable[Path]) -> list[dict[str, Any]]:
    return [_input_file_metadata(path) for path in paths]


def _artifact_input_identity(
    rows: list[dict[str, Any]],
    manifests: dict[str, dict[str, Any]],
    selected_keys: list[str],
    language: str | None,
) -> dict[str, Any]:
    try:
        repository = git_provenance(REPO)
    except (OSError, RuntimeError, ValueError) as error:
        repository = {"status": "unavailable", "error": str(error)}
    manifest_metadata = [
        {
            "language": manifest["language"],
            "path": manifest["_path"],
            "sha256": manifest["_sha256"],
        }
        for manifest in sorted(manifests.values(), key=lambda item: item["language"])
    ]
    return {
        "repository": repository,
        "catalog": _input_file_metadata_rows(sorted(RULES.glob("*.json"))),
        "infrastructure": _input_file_metadata_rows([INFRA, RESOLUTION, APPROVAL]),
        "security_manifests": manifest_metadata,
        "selection": {
            "selected_keys": list(selected_keys),
            "language": language,
        },
        "scanner": {
            "image": SCANNER_IMAGE,
            "digest": SCANNER_IMAGE.rsplit("@", 1)[-1],
            "pull_policy": "never",
        },
        "catalog_security_key_count": len(rows),
    }


def _matrix_case_contract(
    case_results: list[dict[str, Any]],
) -> tuple[list[str], list[str], list[str]]:
    comparisons = [
        result["outcome"]["comparison"]
        for result in case_results
        if isinstance(result.get("outcome"), dict)
        and isinstance(result["outcome"].get("comparison"), str)
    ]
    failing_cases: list[str] = []
    unverified_cases: list[str] = []
    for index, result in enumerate(case_results):
        case_name = result.get("case")
        case_label = case_name if isinstance(case_name, str) else f"case[{index}]"
        outcome = result.get("outcome")
        if (
            result.get("status") != "captured"
            or not isinstance(outcome, dict)
            or not isinstance(outcome.get("comparison"), str)
        ):
            unverified_cases.append(case_label)
        elif outcome["comparison"] != "EXPECTED_MATCH":
            failing_cases.append(case_label)
    return comparisons, failing_cases, unverified_cases


def _matrix_contract_status(
    failing_cases: list[str], unverified_cases: list[str]
) -> str:
    if unverified_cases:
        return "INCOMPLETE"
    if failing_cases:
        return "CONTRACT_MISMATCH"
    return "CONTRACT_MATCH"


def _matrix_limits(case_results: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            limit
            for result in case_results
            for limit in result.get("limits", [])
            if isinstance(limit, str)
        }
    )


def _result_matrix(
    key: str,
    row: dict[str, Any],
    fixture: dict[str, Any] | None,
    rule_metadata: dict[str, Any],
    case_results: list[dict[str, Any]],
) -> dict[str, Any]:
    complete = all(result.get("status") == "captured" for result in case_results)
    comparisons, failing_cases, unverified_cases = _matrix_case_contract(case_results)
    contract_status = _matrix_contract_status(failing_cases, unverified_cases)
    limits = _matrix_limits(case_results)
    negative_control_claimed = complete and any(
        result.get("negative_control_claimed") is True for result in case_results
    )
    return {
        "key": key,
        "language": row["language"],
        "status": "captured" if complete else "incomplete",
        "contract_status": contract_status,
        "contract": {
            "status": contract_status,
            "comparisons": comparisons,
            "failing_cases": sorted(failing_cases),
            "unverified_cases": sorted(unverified_cases),
            "verdict_allowed": False,
        },
        "sensor": {
            "rule_key": key,
            "catalog_kind": rule_metadata.get("catalog_type"),
            "kind": rule_metadata.get("server_type"),
            "edition": "community",
            "endpoint": rule_metadata.get("endpoint"),
        },
        "rule_metadata": rule_metadata,
        "fixture": _public_fixture_row(fixture) if fixture is not None else None,
        "cases": case_results,
        "case_names": [result.get("case") for result in case_results],
        "limits": limits,
        "negative_control_claimed": negative_control_claimed,
        "native_comparison": {
            "status": "NOT_EXECUTED",
            "reason": (
                "native replay is owned by the caller and must use the "
                "recorded native_args with this case-root file set"
            ),
        },
    }


def _execution_status(
    selected_keys: list[str], base: str | None, token_file: Path | None
) -> str:
    if not selected_keys:
        return "not-requested"
    if base is None or token_file is None:
        return "not-configured"
    return "requested"


def _new_artifact(
    rows: list[dict[str, Any]],
    manifests: dict[str, dict[str, Any]],
    selected_keys: list[str],
    language: str | None,
    execute: list[str],
    enterprises: list[dict[str, Any]],
    base: str | None,
    token_file: Path | None,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "security_evidence_schema": SECURITY_EVIDENCE_SCHEMA,
        "generated_by": "tools/oracle/security_evidence.py",
        "input": _artifact_input_identity(rows, manifests, selected_keys, language),
        "execution": {
            "status": _execution_status(selected_keys, base, token_file),
            "requested": list(execute),
            "language": language,
            "selected_keys": selected_keys,
            "case_layout": list(CASE_NAMES),
            "native_replay": {
                "status": "NOT_EXECUTED",
                "owner": "caller",
                "cwd": "materialized-case-root",
                "note": (
                    "native_args are recorded for the owning native replay; "
                    "the reference scanner receives only sonar_properties"
                ),
            },
        },
        "inventory": {
            "security_rule_count": len(rows),
            "classification_counts": {},
            "rows": rows,
        },
        "enterprise_unverified": {
            "count": len(enterprises),
            "rows": enterprises,
        },
        "reference_environment": {
            "status": "not-configured",
            "server": None,
            "community_execution": [],
        },
        "licensed_access": {
            "status": "not-attempted",
            "approval_file": str(APPROVAL.relative_to(REPO)),
            "base_url": "https://codeanalysis.zcdi.dataport.de",
            "required_actions": [
                "catalog-capture",
                "results-data-handling",
                "retention",
            ],
            "limits": [
                "Enterprise analyzer execution was not contacted by this tool",
                "all 17 Enterprise keys remain unverified",
            ],
        },
    }


def _set_classification_counts(
    artifact: dict[str, Any], rows: list[dict[str, Any]]
) -> None:
    counts: dict[str, int] = {}
    for row in rows:
        classification = row["classification"]
        counts[classification] = counts.get(classification, 0) + 1
    artifact["inventory"]["classification_counts"] = dict(sorted(counts.items()))


def _unconfigured_rule_metadata(key: str, row: dict[str, Any]) -> dict[str, Any]:
    rule_type = row["rule_type"]
    return {
        "key": key,
        "catalog_type": rule_type,
        "server_type": rule_type,
        "endpoint": (
            "/api/hotspots/search"
            if rule_type == "SECURITY_HOTSPOT"
            else "/api/issues/search"
        ),
        "classification": row["classification"],
    }


def _store_community_matrix(
    artifact: dict[str, Any],
    row: dict[str, Any],
    matrix: dict[str, Any],
) -> None:
    artifact["reference_environment"]["community_execution"].append(matrix)
    row["community_reference"] = {
        "status": matrix["status"],
        "contract_status": matrix["contract_status"],
        "negative_control_claimed": matrix["negative_control_claimed"],
        "evidence": matrix,
        "limits": matrix["limits"],
    }


def _populate_unconfigured_execution(
    artifact: dict[str, Any],
    selected_keys: list[str],
    by_key: dict[str, dict[str, Any]],
    fixtures: dict[str, dict[str, Any]],
) -> None:
    for key in selected_keys:
        row = by_key[key]
        fixture = fixtures.get(key)
        rule_metadata = _unconfigured_rule_metadata(key, row)
        reason = (
            "Community cannot certify Enterprise-owned rule"
            if row["classification"] == "enterprise-unverified"
            else "reference server credentials were not configured"
        )
        case_results = _unavailable_case_results(key, rule_metadata, fixture, reason)
        matrix = _result_matrix(key, row, fixture, rule_metadata, case_results)
        _store_community_matrix(artifact, row, matrix)


def _server_metadata_or_unavailable(
    base: str, token: str
) -> tuple[dict[str, Any], str | None]:
    try:
        return _server_metadata(base, token), None
    except (OSError, RuntimeError, ValueError) as error:
        server = {
            "url": base.rstrip("/"),
            "status": "UNAVAILABLE",
            "edition": None,
            "plugins": [],
        }
        return server, f"reference server metadata unavailable: {error}"


def _configured_rule_metadata(
    key: str, row: dict[str, Any], server: dict[str, Any]
) -> dict[str, Any]:
    catalog_type = row["rule_type"]
    return {
        "key": key,
        "catalog_type": catalog_type,
        "classification": row["classification"],
        "server": server,
        "server_version": server.get("version"),
        "server_type": catalog_type,
        "hotspot_endpoint": catalog_type == "SECURITY_HOTSPOT",
        "endpoint": (
            "/api/hotspots/search"
            if catalog_type == "SECURITY_HOTSPOT"
            else "/api/issues/search"
        ),
    }


def _server_error_case_results(
    key: str,
    rule_metadata: dict[str, Any],
    fixture: dict[str, Any] | None,
    server_error: str,
) -> list[dict[str, Any]]:
    return [
        _case_result(
            _case_common(key, case_name, rule_metadata, fixture),
            "incomplete",
            [server_error],
        )
        for case_name in _fixture_case_names(fixture)
    ]


def _configured_case_results(
    base: str,
    token: str,
    key: str,
    row: dict[str, Any],
    fixture: dict[str, Any] | None,
    rule_metadata: dict[str, Any],
    server: dict[str, Any],
    server_error: str | None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if row["classification"] == "enterprise-unverified":
        case_results = _unavailable_case_results(
            key,
            rule_metadata,
            fixture,
            "Community cannot certify Enterprise-owned rule",
        )
    elif server_error is not None:
        case_results = _server_error_case_results(
            key, rule_metadata, fixture, server_error
        )
    else:
        try:
            rule_metadata = _server_rule_metadata(
                base, token, key, catalog_type=row["rule_type"]
            )
            rule_metadata.update(
                {
                    "classification": row["classification"],
                    "server": server,
                    "server_version": server.get("version"),
                }
            )
            case_results = [
                _run_reference_case(
                    base,
                    token,
                    key,
                    case_name,
                    dict(rule_metadata),
                    fixture,
                )
                for case_name in _fixture_case_names(fixture)
            ]
        except (OSError, RuntimeError, ValueError) as error:
            reason = f"live rule metadata unavailable: {error}"
            case_results = [
                _case_result(
                    _case_common(key, case_name, rule_metadata, fixture),
                    "incomplete",
                    [reason],
                )
                for case_name in _fixture_case_names(fixture)
            ]
    return rule_metadata, case_results


def _populate_configured_execution(
    artifact: dict[str, Any],
    selected_keys: list[str],
    by_key: dict[str, dict[str, Any]],
    fixtures: dict[str, dict[str, Any]],
    base: str,
    token: str,
    server: dict[str, Any],
    server_error: str | None,
) -> None:
    for key in selected_keys:
        row = by_key[key]
        fixture = fixtures.get(key)
        rule_metadata = _configured_rule_metadata(key, row, server)
        rule_metadata, case_results = _configured_case_results(
            base,
            token,
            key,
            row,
            fixture,
            rule_metadata,
            server,
            server_error,
        )
        matrix = _result_matrix(key, row, fixture, rule_metadata, case_results)
        _store_community_matrix(artifact, row, matrix)


def build_artifact(
    *,
    base: str | None = None,
    token_file: Path | None = None,
    execute: list[str] = (),
    language: str | None = None,
) -> dict[str, Any]:
    rows = _catalog_security_rows()
    manifests = load_security_fixture_manifests()
    fixtures = load_security_fixtures()
    selected_keys = _resolve_execution_keys(execute, language, rows, fixtures)
    enterprises = _enterprise_rows(rows)
    artifact = _new_artifact(
        rows,
        manifests,
        selected_keys,
        language,
        execute,
        enterprises,
        base,
        token_file,
    )
    _set_classification_counts(artifact, rows)
    by_key = {row["key"]: row for row in rows}
    if base is None or token_file is None:
        _populate_unconfigured_execution(artifact, selected_keys, by_key, fixtures)
        return artifact
    token = _token_from(token_file)
    server, server_error = _server_metadata_or_unavailable(base, token)
    _apply_server_context(rows, server)
    artifact["reference_environment"] = {
        "status": "available" if server.get("status") == "UP" else "unavailable",
        "server": server,
        "community_execution": [],
    }
    if server_error is not None:
        artifact["reference_environment"]["limits"] = [server_error]
    _populate_configured_execution(
        artifact,
        selected_keys,
        by_key,
        fixtures,
        base,
        token,
        server,
        server_error,
    )
    artifact["execution"]["status"] = "complete" if selected_keys else "not-requested"
    return artifact


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--url", default=os.environ.get("SONAR_ORACLE_URL"))
    parser.add_argument("--token-file", type=Path)
    parser.add_argument(
        "--execute",
        action="append",
        metavar="KEY|LANGUAGE",
        help="execute one manifest key, language, or analyzer prefix (repeatable)",
    )
    parser.add_argument(
        "--language",
        metavar="LANGUAGE",
        help="restrict execution selection to one manifest language",
    )
    args = parser.parse_args()
    if (args.execute or args.language) and (not args.url or args.token_file is None):
        parser.error("--execute/--language requires --url and --token-file")
    try:
        artifact = build_artifact(
            base=args.url,
            token_file=args.token_file,
            execute=args.execute or (),
            language=args.language,
        )
    except (OSError, RuntimeError, ValueError) as error:
        parser.error(str(error))
    write_json_atomic(args.output, artifact, indent=1)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "security_rule_count": artifact["inventory"]["security_rule_count"],
                "enterprise_unverified_count": artifact["enterprise_unverified"][
                    "count"
                ],
                "community_execution_count": len(
                    artifact["reference_environment"]["community_execution"]
                ),
                "selected_key_count": len(artifact["execution"]["selected_keys"]),
                "execution_status": artifact["execution"]["status"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
