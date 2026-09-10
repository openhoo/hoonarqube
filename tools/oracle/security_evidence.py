#!/usr/bin/env python3
"""Inventory security rules and capture bounded Community sensor evidence.

This tool never treats a direct compiler oracle as a server security sensor and
never turns Community execution into Enterprise parity.  It can run synthetic
fixtures against a caller-selected Community SonarQube server when explicitly
requested with ``--execute``; otherwise it emits a complete inventory with
unexecuted/unavailable limits.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any
from fetch_issues import fetch_security
from parity import (
    SECURITY_EVIDENCE_SCHEMA,
    load_infra_boundaries,
    parse_report_task,
    read_json,
    read_jsonl,
    read_secret_file,
    wait_for_compute_engine as wait_for_compute_engine_helper,
    write_json_atomic,
)


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
PLUGIN_OWNER = {
    "csharp": {
        "community": "SonarAnalyzer.CSharp.dll / C# server sensor",
        "enterprise_security": "securitycsharpfrontend",
    },
    "javascript": {
        "community": "javascript server sensor (JavaScript/TypeScript/CSS)",
        "enterprise_security": "securityjsfrontend",
    },
    "typescript": {
        "community": "javascript server sensor (JavaScript/TypeScript/CSS)",
        "enterprise_security": "securityjsfrontend",
    },
    "python": {
        "community": "python server sensor",
        "enterprise_security": "securitypythonfrontend",
    },
    "go": {
        "community": "go server sensor",
        "enterprise_security": "securitygofrontend",
    },
    "rust": {
        "community": "rust server sensor",
        "enterprise_security": "rust server sensor",
    },
}
ORACLE_PROJECT_DIR = {
    "csharp": "oracle-cs",
    "javascript": "oracle-js",
    "typescript": "oracle-ts",
    "python": "oracle-py",
    "go": "oracle-go",
    "rust": "oracle-rust",
}
COMMUNITY_PLUGIN_KEY = {
    "csharp": "csharp",
    "javascript": "javascript",
    "typescript": "javascript",
    "python": "python",
    "go": "go",
    "rust": "rust",
}
REFERENCE_CASES = {
    "python:S2077": {
        "attack": "oracle-py/src/s2077_bad.py",
        "safe": "oracle-py/src/s2077_good.py",
        "near_miss": (
            "class Cursor:\n"
            "    def execute(self, statement):\n"
            "        return statement\n"
            "\n"
            "uid = 7\n"
            "cursor = Cursor()\n"
            'cursor.execute(f"SELECT * FROM t WHERE id={uid}")\n'
        ),
    },
    "javascript:S2077": {
        "attack": "oracle-js/src/s2077_bad.js",
        "safe": "oracle-js/src/s2077_good.js",
        "near_miss": (
            "function query(statement) {\n"
            "    return statement;\n"
            "}\n"
            "\n"
            "function run(input) {\n"
            "    return query(`SELECT * FROM users WHERE name = ${input}`);\n"
            "}\n"
        ),
    },
    "typescript:S2077": {
        "attack": "oracle-ts/src/s2077_bad.ts",
        "safe": "oracle-ts/src/s2077_good.ts",
        "near_miss": (
            "function query(statement: string): string {\n"
            "    return statement;\n"
            "}\n"
            "\n"
            "function run(input: string): string {\n"
            "    return query(`SELECT * FROM users WHERE name = ${input}`);\n"
            "}\n"
        ),
    },
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
    "python": {"language": "py", "name": "Hoonarqube Oracle All py"},
    "javascript": {"language": "js", "name": "Hoonarqube Oracle All js"},
    "typescript": {"language": "ts", "name": "Hoonarqube Oracle All ts"},
}

REFERENCE_SOURCES = {
    "python:S2077": {
        "attack": (
            "from django.db import connection\n"
            "value = input()\n"
            "with connection.cursor() as cursor:\n"
            '    cursor.execute("{0}".format(value))\n'
        ),
        "safe": (
            "from django.db import connection\n"
            "value = input()\n"
            "with connection.cursor() as cursor:\n"
            '    cursor.execute("SELECT * FROM users WHERE id=%s", (value,))\n'
        ),
        "near_miss": (
            "from django.db import connection\n"
            "value = input()\n"
            "def run(cursor, value):\n"
            '    query = "SELECT * FROM users WHERE id=%s"\n'
            "    cursor.execute(query, (value,))\n"
            "with connection.cursor() as cursor:\n"
            "    run(cursor, value)\n"
        ),
    },
    "javascript:S2077": {
        "attack": (
            "const mysql = require('mysql');\n"
            "const mycon = mysql.createConnection({});\n"
            "const userinput = process.env.USER_INPUT;\n"
            "mycon.connect(function(err) {\n"
            "    mycon.query('SELECT * FROM users WHERE id = ' + userinput, (err, res) => {});\n"
            "});\n"
        ),
        "safe": (
            "const pg = require('pg');\n"
            "const pgcon = new pg.Client({});\n"
            "const userinput = process.env.USER_INPUT;\n"
            "pgcon.query('SELECT * FROM users WHERE id = $1', [userinput]);\n"
        ),
        "near_miss": (
            "const pg = require('pg');\n"
            "const pgcon = new pg.Client({});\n"
            "function run(value) {\n"
            "  return pgcon.query('SELECT * FROM users WHERE id = $1', [value]);\n"
            "}\n"
            "run(process.env.USER_INPUT);\n"
        ),
    },
    "typescript:S2077": {
        "attack": (
            "const mysql = require('mysql');\n"
            "const mycon = mysql.createConnection({});\n"
            "const userinput = process.env.USER_INPUT as string;\n"
            "mycon.connect(function(err) {\n"
            "    mycon.query('SELECT * FROM users WHERE id = ' + userinput, (err, res) => {});\n"
            "});\n"
        ),
        "safe": (
            "import pg from 'pg';\n"
            "const pgcon = new pg.Client({});\n"
            "const userinput = process.env.USER_INPUT as string;\n"
            "pgcon.query('SELECT * FROM users WHERE id = $1', [userinput]);\n"
        ),
        "near_miss": (
            "import pg from 'pg';\n"
            "const pgcon = new pg.Client({});\n"
            "function run(value: string) {\n"
            "  return pgcon.query('SELECT * FROM users WHERE id = $1', [value]);\n"
            "}\n"
            "run(process.env.USER_INPUT as string);\n"
        ),
    },
}


def _required_text(value: Any, key: str, context: str) -> str:
    field = value.get(key) if isinstance(value, dict) else None
    if not isinstance(field, str) or not field.strip():
        raise ValueError(f"{context} {key} must be a non-empty string")
    return field


def _fixture_records(language: str) -> dict[str, dict[str, Any]]:
    project_name = ORACLE_PROJECT_DIR.get(language, f"oracle-{language}")
    project = REPO / ".oracle" / "sonar" / "projects" / project_name
    expected = project / "expected.jsonl"
    records: dict[str, dict[str, Any]] = {}
    if not expected.is_file():
        return records
    for index, record in enumerate(read_jsonl(expected)):
        if not isinstance(record, dict):
            raise ValueError(f"{expected} row {index} must be an object")
        key = _required_text(record, "key", f"{expected} row {index}")
        records[key] = record
    return records


def _catalog_security_rows() -> list[dict[str, Any]]:
    infra = load_infra_boundaries(INFRA)
    rows: list[dict[str, Any]] = []
    for catalog_path in sorted(RULES.glob("*.json")):
        language = catalog_path.stem
        catalog = read_json(catalog_path)
        if not isinstance(catalog, dict) or not isinstance(catalog.get("rules"), list):
            raise ValueError(f"{catalog_path} must contain a rules list")
        fixtures = _fixture_records(language)
        for index, rule in enumerate(catalog["rules"]):
            if not isinstance(rule, dict):
                raise ValueError(f"{catalog_path} rule {index} must be an object")
            key = _required_text(rule, "external_key", f"{catalog_path} rule {index}")
            rule_type = _required_text(
                rule, "rule_type", f"{catalog_path} rule {index}"
            )
            if rule_type not in SECURITY_TYPES:
                continue
            classification = _required_text(
                rule, "classification", f"{catalog_path} rule {index}"
            )
            boundary = infra.get(key)
            fixture = fixtures.get(key)
            context_limits: list[str] = []
            if boundary is not None:
                context_limits.append(boundary)
            if fixture is None:
                context_limits.append("no dedicated oracle fixture row")
            server_sensor_plugin = _server_sensor_plugin(language, classification)
            rows.append(
                {
                    "key": key,
                    "language": language,
                    "rule_type": rule_type,
                    "classification": classification,
                    "implementation": {
                        "catalog_row": True,
                        "fixture_row": fixture is not None,
                        "fixture": fixture,
                    },
                    "sensor_ownership": {
                        "direct_analyzer": PLUGIN_OWNER[language]["community"],
                        "server_security_sensor": server_sensor_plugin,
                    },
                    "edition": {
                        "community_reference": classification == "community-base",
                        "enterprise_reference_required": classification
                        == "enterprise-unverified",
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
            )

    return rows


def _enterprise_rows(catalog_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    resolution = read_json(RESOLUTION)
    if not isinstance(resolution, dict):
        raise ValueError("community artifact resolution must be an object")
    raw = resolution.get("enterprise_unverified_rules")
    if not isinstance(raw, dict) or not isinstance(raw.get("csharp"), list):
        raise ValueError("enterprise resolution must contain csharp keys")
    catalog_by_key = {row["key"]: row for row in catalog_rows}
    rows: list[dict[str, Any]] = []
    for key in raw["csharp"]:
        if not isinstance(key, str) or not key:
            raise ValueError("enterprise rule key must be a non-empty string")
        local = catalog_by_key.get(key)
        rows.append(
            {
                "key": key,
                "language": "csharp",
                "rule_type": local["rule_type"]
                if local
                else "not-in-security-inventory",
                "security_inventory_row": local is not None,
                "sensor_owner": "SonarAnalyzer.Enterprise.CSharp.dll",
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
        )
    return rows


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
    import base64

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
    import base64

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
    import base64

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


def _profile_metadata(base: str, token: str, language: str) -> dict[str, Any]:
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
    marker = "<key>S2077</key>"
    return {
        "language": profile["language"],
        "name": profile["name"],
        "key": selected.get("key"),
        "active_rule_count": selected.get("activeRuleCount"),
        "s2077_active": marker in backup,
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


def _server_rule_metadata(base: str, token: str, key: str) -> dict[str, Any]:
    payload = _api_json(base, token, "/api/rules/show", {"key": key})
    rule = payload.get("rule") if isinstance(payload, dict) else None
    if not isinstance(rule, dict):
        raise RuntimeError(f"reference rule metadata missing for {key}")
    rule_type = rule.get("type")
    if not isinstance(rule_type, str) or not rule_type:
        raise RuntimeError(f"reference rule metadata has no type for {key}")
    return {
        "key": key,
        "catalog_type": "SECURITY_HOTSPOT",
        "server_type": rule_type,
        "server_status": rule.get("status"),
        "server_tags": rule.get("tags", []),
        "hotspot_endpoint": rule_type == "SECURITY_HOTSPOT",
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


def _case_language(key: str) -> str:
    return key.split(":", 1)[0]


def _verify_scanner_image() -> tuple[bool, str]:
    image_name = SCANNER_IMAGE.split("@", 1)[0]
    try:
        inspected = subprocess.run(
            [
                "podman",
                "image",
                "inspect",
                "--format",
                "{{index .RepoDigests 0}}",
                image_name,
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
    resolved = inspected.stdout.strip()
    if inspected.returncode != 0 or resolved != SCANNER_IMAGE:
        return False, "local scanner image digest does not match pinned digest"
    return True, resolved


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
    comparison: str | None = None,
    finding_count: int | None = None,
    target_rules: list[str] | None = None,
) -> dict[str, Any]:
    detected = case_name == "attack"
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
    result = {
        **common,
        "status": status,
        "limits": limits,
        "project": project,
        "scanner_digest": scanner_digest,
    }
    if compute_engine is not _MISSING:
        result["compute_engine"] = compute_engine
    result["evidence"] = evidence
    return result


def _reference_source(
    key: str, case_name: str
) -> tuple[bytes | None, str | None, str | None, str | None]:
    case_matrix = REFERENCE_CASES.get(key)
    source_value = case_matrix.get(case_name) if isinstance(case_matrix, dict) else None
    source_override = REFERENCE_SOURCES.get(key, {}).get(case_name)
    if source_override is not None:
        source_value = source_override
    if not isinstance(source_value, str) or not source_value:
        return (
            None,
            None,
            None,
            f"no approved synthetic {case_name} case is defined",
        )
    language = _case_language(key)
    suffix = {"python": ".py", "javascript": ".js", "typescript": ".ts"}[language]
    if source_override is not None:
        return (
            source_override.encode("utf-8"),
            f"{key.split(':', 1)[1].lower()}_{case_name}{suffix}",
            "inline-approved-trigger",
            None,
        )
    if case_name == "near_miss":
        return (
            source_value.encode("utf-8"),
            f"{key.split(':', 1)[1].lower()}_near_miss{suffix}",
            "inline-fixture",
            None,
        )
    source = REPO / ".oracle" / "sonar" / "projects" / source_value
    if not source.is_file():
        return (
            None,
            None,
            None,
            f"synthetic source is missing: {source_value}",
        )
    return source.read_bytes(), source.name, "repository-fixture", None


def _prepare_reference_profile(
    base: str,
    token: str,
    project: str,
    rule_metadata: dict[str, Any],
) -> tuple[dict[str, Any] | None, str | None]:
    profile = rule_metadata.get("profile")
    if not isinstance(profile, dict) or not profile.get("s2077_active"):
        return None, "S2077 is not proven active in the selected Community profile"
    try:
        association = _associate_project_profile(base, token, project, profile)
    except (OSError, RuntimeError, ValueError) as error:
        return None, f"project/profile association failed: {error}"
    return {**rule_metadata, "profile_association": association}, None


def _run_scanner(
    base: str,
    token: str,
    project: str,
    language: str,
    source_text: bytes,
    source_name: str,
) -> tuple[int | None, str | None, str | None]:
    with (
        tempfile.TemporaryDirectory(prefix=f"issue44-{language}-") as directory,
        tempfile.TemporaryDirectory(prefix="issue44-env-") as env_directory,
        tempfile.TemporaryDirectory(prefix="issue44-work-") as work_directory,
    ):
        root = Path(directory)
        destination = root / source_name
        destination.write_bytes(source_text)
        root.chmod(0o755)
        destination.chmod(0o644)
        work = Path(work_directory)
        work.chmod(0o755)
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
            "-Dsonar.sources=.",
            f"-Dsonar.host.url={base}",
            "-Dsonar.working.directory=/tmp/sonar",
        ]
        try:
            completed = subprocess.run(
                command,
                cwd=REPO,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=900,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            return None, None, f"Community scanner execution failed: {error}"
        report_task_path = work / "report-task.txt"
        report_task_text = (
            report_task_path.read_text(encoding="utf-8")
            if report_task_path.is_file()
            else None
        )
    return completed.returncode, report_task_text, None


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
    if return_code != 0:
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
    finding_count = len(findings)
    if case_name == "attack":
        comparison = "EXPECTED_MATCH" if finding_count > 0 else "UNEXPECTED_MISS"
    else:
        comparison = "EXPECTED_MATCH" if finding_count == 0 else "UNEXPECTED_FINDING"
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
        comparison=comparison,
        finding_count=finding_count,
        target_rules=target_rules,
    )
    return {
        **common,
        "status": "captured",
        "negative_control_claimed": False,
        "outcome": outcome,
        "limits": list(evidence["limits"]),
        "project": project,
        "scanner_digest": image_identity,
        "compute_engine": compute_engine,
        "evidence": evidence,
    }


def _run_reference_case(
    base: str,
    token: str,
    key: str,
    case_name: str,
    rule_metadata: dict[str, Any],
) -> dict[str, Any]:
    observed_type = rule_metadata.get("server_type")
    hotspot_endpoint = observed_type == "SECURITY_HOTSPOT"
    common = {
        "key": key,
        "case": case_name,
        "sensor": {
            "rule_key": key,
            "catalog_kind": rule_metadata.get("catalog_type"),
            "kind": observed_type,
            "edition": "community",
            "endpoint": "hotspots" if hotspot_endpoint else "issues",
        },
        "rule_metadata": rule_metadata,
        "scanner_image": SCANNER_IMAGE,
    }
    common["outcome"] = _case_outcome(key, case_name)
    source_text, source_name, source_kind, source_limit = _reference_source(
        key, case_name
    )
    if source_limit is not None:
        return _case_result(common, "unavailable", [source_limit])
    common["source"] = {
        "kind": source_kind,
        "name": source_name,
        "sha256": hashlib.sha256(source_text).hexdigest(),
    }
    image_available, image_identity = _verify_scanner_image()
    if not image_available:
        return _case_result(common, "unavailable", [image_identity])
    language = _case_language(key)
    project = (
        f"hoonarqube-issue44-{language}-{case_name.replace('_', '-')}-"
        f"{uuid.uuid4().hex[:12]}"
    )
    case_metadata, profile_limit = _prepare_reference_profile(
        base, token, project, rule_metadata
    )
    if profile_limit is not None:
        return _case_result(
            common,
            "incomplete",
            [profile_limit],
            project=project,
            scanner_digest=image_identity,
        )
    common["profile_association"] = case_metadata["profile_association"]
    common["rule_metadata"] = case_metadata
    return_code, report_task_text, scanner_limit = _run_scanner(
        base, token, project, language, source_text, source_name
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


def build_artifact(
    *,
    base: str | None = None,
    token_file: Path | None = None,
    execute: list[str] = (),
) -> dict[str, Any]:
    rows = _catalog_security_rows()
    enterprises = _enterprise_rows(rows)
    artifact: dict[str, Any] = {
        "schema_version": 1,
        "security_evidence_schema": SECURITY_EVIDENCE_SCHEMA,
        "generated_by": "tools/oracle/security_evidence.py",
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
    counts: dict[str, int] = {}
    for row in rows:
        classification = row["classification"]
        counts[classification] = counts.get(classification, 0) + 1
    artifact["inventory"]["classification_counts"] = dict(sorted(counts.items()))
    if base is None or token_file is None:
        return artifact
    token = _token_from(token_file)
    server = _server_metadata(base, token)
    _apply_server_context(rows, server)
    artifact["reference_environment"] = {
        "status": "available" if server.get("status") == "UP" else "unavailable",
        "server": server,
        "community_execution": [],
    }
    by_key = {row["key"]: row for row in rows}
    for key in execute:
        try:
            rule_metadata = _server_rule_metadata(base, token, key)
            rule_metadata["profile"] = _profile_metadata(
                base, token, _case_language(key)
            )
            sensor_available, sensor_limit = _community_sensor_gate(
                server, _case_language(key)
            )
            if not sensor_available:
                case_results = [
                    {
                        "key": key,
                        "case": case_name,
                        "status": "unavailable",
                        "outcome": _case_outcome(key, case_name),
                        "limits": [sensor_limit],
                        "project": None,
                        "evidence": None,
                    }
                    for case_name in ("attack", "safe", "near_miss")
                ]
            else:
                case_results = [
                    _run_reference_case(base, token, key, case_name, rule_metadata)
                    for case_name in ("attack", "safe", "near_miss")
                ]
        except (OSError, RuntimeError, ValueError) as error:
            rule_metadata = {
                "key": key,
                "catalog_type": "SECURITY_HOTSPOT",
                "server_type": None,
                "hotspot_endpoint": None,
            }
            case_results = [
                {
                    "key": key,
                    "case": case_name,
                    "status": "incomplete",
                    "outcome": _case_outcome(key, case_name),
                    "limits": [f"live rule metadata unavailable: {error}"],
                    "project": None,
                    "evidence": None,
                }
                for case_name in ("attack", "safe", "near_miss")
            ]
        complete = all(result["status"] == "captured" for result in case_results)
        comparisons = [
            result.get("outcome", {}).get("comparison")
            for result in case_results
            if isinstance(result.get("outcome"), dict)
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
        contract_status = (
            "INCOMPLETE"
            if unverified_cases
            else "CONTRACT_MISMATCH"
            if failing_cases
            else "CONTRACT_MATCH"
        )
        matrix = {
            "key": key,
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
                "endpoint": (
                    "hotspots" if rule_metadata.get("hotspot_endpoint") else "issues"
                ),
            },
            "rule_metadata": rule_metadata,
            "cases": case_results,
            "limits": sorted(
                {limit for result in case_results for limit in result.get("limits", [])}
            ),
            "negative_control_claimed": False,
        }
        artifact["reference_environment"]["community_execution"].append(matrix)
        row = by_key.get(key)
        if row is not None:
            row["community_reference"] = {
                "status": matrix["status"],
                "contract_status": matrix["contract_status"],
                "negative_control_claimed": False,
                "evidence": matrix,
                "limits": matrix["limits"],
            }
    return artifact


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--url", default=os.environ.get("SONAR_ORACLE_URL"))
    parser.add_argument("--token-file", type=Path)
    parser.add_argument("--execute", action="append", choices=sorted(REFERENCE_CASES))
    args = parser.parse_args()
    if args.execute and (not args.url or args.token_file is None):
        parser.error("--execute requires --url and --token-file")
    artifact = build_artifact(
        base=args.url,
        token_file=args.token_file,
        execute=args.execute or (),
    )
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
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
