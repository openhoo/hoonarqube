#!/usr/bin/env python3
"""Summarize a live SonarQube public corpus capture without source or credentials."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from collections import Counter, defaultdict
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path

from parity import read_json, write_json_atomic
from public_corpus_capture import verify_checkout
from real_project_suite import (
    digest,
    file_metric_comparison,
    metric_comparison,
    normalized_path,
)

REPO = Path(__file__).resolve().parents[2]
INFRA = "catalog/infra-boundaries.json"
JSON_FORMAT_VERSION = 1
SENSOR_FAILURE = re.compile(
    r"\b(?:parsing error|failed to parse|unable to parse|cannot parse|"
    r"error while parsing|could not parse|failed to analyze file)\b",
    re.IGNORECASE,
)
JS_LANGUAGES = {"javascript", "typescript", "js", "ts", "jsx", "tsx"}


def canonical_sha(value):
    canonical = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def count_tree(items):
    return dict(sorted(Counter(items).items()))


def source_indexes(folder, root, label):
    files = {}
    for entry in read_json(folder / f"{label}-source-files.json"):
        path = normalized_path(entry["path"])
        source = (root / path).resolve()
        if (
            path in files
            or not source.is_relative_to(root)
            or digest(source) != entry["sha256"]
        ):
            raise ValueError(f"invalid {label} source index")
        files[path] = entry["sha256"]
    return files


def scan_result(folder, progress):
    path = folder / "scanner-execution.json"
    if not path.exists():
        return {"state": progress["reference"]["status"]}
    scanner = read_json(path)
    ce = (
        read_json(folder / "compute-engine.json")["task"]
        if (folder / "compute-engine.json").exists()
        else {}
    )
    stdout = folder / "scanner.stdout"
    if digest(stdout) != scanner["stdout_sha256"]:
        raise ValueError("scanner log differs from execution receipt")
    log = stdout.read_text(errors="replace")
    failures = [
        line
        for line in log.splitlines()
        if (" WARN " in line or " ERROR " in line) and SENSOR_FAILURE.search(line)
    ]
    state = progress["reference"]["status"]
    if state == "complete":
        if scanner["exit_code"] != 0 or ce.get("status") != "SUCCESS":
            raise ValueError(
                "reference completion requires successful scanner and compute task"
            )
        if failures:
            state = "incomplete"
    return {
        "state": state,
        "scanner_seconds": round(scanner["seconds"], 3),
        "scanner_and_compute_seconds": progress["reference"].get(
            "scanner_and_ce_seconds"
        ),
        "compute_status": ce.get("status"),
        "compute_ms": ce.get("executionTimeMs"),
        "parse_warning_lines": len(failures),
    }


def check_profiles(folder, effective):
    result = {}
    for scanned in read_json(folder / "profiles.json")["profiles"]:
        language = scanned["language"]
        profile = effective[language]
        captured_pages = sorted(folder.glob(f"active-{language}-page-*.json"))
        observed = {r["key"] for p in captured_pages for r in read_json(p)["rules"]}
        if (
            scanned["key"] != profile["profile_key"]
            or scanned["name"] != profile["name"]
            or scanned["isBuiltIn"] != profile["builtin"]
            or observed != profile["rules"].keys()
            or scanned["activeRuleCount"] != len(observed)
        ):
            raise ValueError(
                f"captured {language} profile does not match effective settings"
            )
        for key, rule in profile["rules"].items():
            if key in result and rule != result[key]:
                raise ValueError(
                    f"rule appears under different profile settings: {key}"
                )
            result[key] = rule
    return result


def utf16_coordinates(issue, source_lines):
    values = tuple(
        issue["range"][endpoint][position]
        for endpoint in ("start", "end")
        for position in ("line", "column")
    )
    if values == (0, 0, 0, 0):
        return (None, None, None, None)
    start_line, start_column, end_line, end_column = values
    if (start_line, start_column) > (end_line, end_column):
        raise ValueError("reversed native range")
    coords = []
    for line, column in ((start_line, start_column), (end_line, end_column)):
        if not (1 <= line <= len(source_lines)):
            raise ValueError("native line outside captured source")
        content = source_lines[line - 1]
        if not (0 <= column <= len(content)):
            raise ValueError("native column outside captured source")
        coords.extend((line, len(content[:column].encode("utf-16-le")) // 2))
    return tuple(coords)


def normalize_native(files, root, native_catalog, profiles):
    ordinary, messages, hotspots, invalid = Counter(), Counter(), Counter(), Counter()
    for file in files:
        path = normalized_path(file["path"])
        if not file["issues"]:
            continue
        text = (root / path).read_bytes().decode("utf-8")
        breaks = (
            r"\r\n|[\n\r\u2028\u2029]"
            if file["language"].lower() in JS_LANGUAGES
            else r"\r?\n"
        )
        source_lines = re.split(breaks, text)
        for issue in file["issues"]:
            rule = issue["rule_key"]
            if (
                native_catalog.get(rule) == "SECURITY_HOTSPOT"
                or profiles.get(rule, {}).get("type") == "SECURITY_HOTSPOT"
            ):
                hotspots[rule] += 1
                continue
            try:
                coordinates = utf16_coordinates(issue, source_lines)
            except ValueError:
                invalid[rule, path] += 1
                continue
            identity = (rule, path, *coordinates)
            ordinary[identity] += 1
            messages[(*identity, issue["message"])] += 1
    return ordinary, messages, hotspots, invalid


def normalize_reference(issues, project_key, reference_index):
    ordinary, messages, project_level, unindexed = (
        Counter(),
        Counter(),
        Counter(),
        Counter(),
    )
    for issue in issues:
        component, rule = issue["component"], issue["rule"]
        if component == project_key:
            project_level[rule] += 1
            continue
        if not component.startswith(project_key + ":"):
            raise ValueError("unexpected reference project")
        path = normalized_path(component[len(project_key) + 1 :])
        if path not in reference_index:
            unindexed[rule, path] += 1
            continue
        span = issue.get("textRange")
        coordinates = (
            tuple(span[k] for k in ("startLine", "startOffset", "endLine", "endOffset"))
            if span is not None
            else (None, None, None, None)
        )
        identity = (rule, path, *coordinates)
        ordinary[identity] += 1
        messages[(*identity, issue["message"])] += 1
    return ordinary, messages, project_level, unindexed


def by_rule(native, reference, key_class):
    rows = defaultdict(Counter)
    for identity in sorted(native.keys() | reference.keys(), key=repr):
        rule = identity[0]
        ours, theirs = native.get(identity, 0), reference.get(identity, 0)
        rows[rule].update(
            {
                "matched": min(ours, theirs),
                "native_only": max(0, ours - theirs),
                "reference_only": max(0, theirs - ours),
            }
        )
    totals = Counter()
    classes = defaultdict(Counter)
    for key, counts in rows.items():
        totals.update(counts)
        classes[key_class(key)].update(counts)
    return {
        "matched": totals["matched"],
        "native_only": totals["native_only"],
        "reference_only": totals["reference_only"],
        "by_class": {key: dict(counter) for key, counter in sorted(classes.items())},
        "by_rule": {
            key: {"class": key_class(key), **{k: v for k, v in counter.items() if v}}
            for key, counter in sorted(rows.items())
        },
    }


def metrics_summary(folder, native, exact_scope):
    reference = read_json(folder / "measures.json")["component"]["measures"]
    aggregate = metric_comparison(native["project"]["metrics"], reference)
    duplication = {}
    native_duplication = native["project"]["duplication"] or {}
    for row in reference:
        metric = row["metric"]
        if metric not in {
            "duplicated_lines",
            "duplicated_blocks",
            "duplicated_lines_density",
        }:
            continue
        value = native_duplication.get(metric)
        reference_value = Decimal(row["value"])
        observed_value = None if value is None else Decimal(str(value))
        if metric.endswith("_density") and observed_value is not None:
            observed_value = observed_value.quantize(
                Decimal("0.1"), rounding=ROUND_HALF_UP
            )
        duplication[metric] = {
            "native": value,
            "reference": float(reference_value)
            if metric.endswith("_density")
            else int(reference_value),
            "matched": observed_value == reference_value,
        }
    ref_files = read_json(folder / "file-metrics.json")
    file_values = file_metric_comparison(native["files"], ref_files)
    ref_metrics = {normalized_path(row["path"]): row["measures"] for row in ref_files}
    compared_cells = sum(
        sum(
            m["metric"] in {"lines", "ncloc", "comment_lines"}
            for m in ref_metrics[normalized_path(file["path"])]
        )
        for file in native["files"]
        if normalized_path(file["path"]) in ref_metrics
    )
    return {
        "whole_scope_values_comparable": exact_scope,
        "aggregate": aggregate,
        "duplication": duplication,
        "shared_file_metrics": {
            "files": file_values["matched_files"],
            "compared_cells": compared_cells,
            "matched_cells": file_values["matched_cells"],
            "different_files": len(file_values["differences"]),
        },
    }


def replay_source(reference_row, native_row):
    """Only the local checkout path may differ between captures."""
    if reference_row == native_row:
        return native_row
    if {**native_row, "path": reference_row["path"]} != reference_row:
        raise ValueError("replay source manifest differs from the reference capture")
    verify_checkout(native_row)
    return native_row


def evidence_digests(folder, native_folder):
    evidence_names = (
        "source.json",
        "compute-engine.json",
        "scanner-execution.json",
        "scanner.stdout",
        "issues.json",
        "hotspots.json",
        "measures.json",
        "file-metrics.json",
        "reference-source-files.json",
        "native-execution.json",
        "native.stdout",
        "native-source-files.json",
    )
    evidence_paths = {
        f: (
            native_folder if f.startswith("native-") or f == "native.stdout" else folder
        )
        / f
        for f in evidence_names
    }
    inventory = {
        f: digest(path) for f, path in evidence_paths.items() if path.is_file()
    }
    if native_folder != folder:
        inventory["native-source-manifest.json"] = digest(native_folder / "source.json")
    return inventory


def project_metadata(folder, native_folder):
    progress = read_json(folder / "progress.json")
    row = replay_source(
        read_json(folder / "source.json"), read_json(native_folder / "source.json")
    )
    native_progress = read_json(native_folder / "progress.json")
    if native_progress["native"]["status"] == "complete" and not native_progress.get(
        "ended_at_utc"
    ):
        raise ValueError(
            "complete native capture is missing its final checkout postcheck"
        )
    result = {
        "source": {
            k: row[k]
            for k in (
                "name",
                "repository",
                "ref",
                "commit",
                "tree",
                "project_key",
                "sources",
                "exclude",
                "language",
            )
        },
        "started_at_utc": progress["started_at_utc"],
        "ended_at_utc": progress.get("ended_at_utc"),
        "reference": scan_result(folder, progress),
        "native": {k: v for k, v in native_progress["native"].items() if k != "reason"},
    }
    if native_folder != folder:
        result["native"]["started_at_utc"] = native_progress["started_at_utc"]
        result["native"]["ended_at_utc"] = native_progress.get("ended_at_utc")
    if row.get("variant_of"):
        result["source"]["variant_of"] = row["variant_of"]
    if "java_context_sha256" in row:
        result["java_context_sha256"] = row["java_context_sha256"]
        result["java_release"] = row["java_release"]
    native = reference_issues = None
    native_path = native_folder / "native.json"
    if native_path.exists():
        native = read_json(native_path)
        native_exec = read_json(native_folder / "native-execution.json")
        if digest(native_folder / "native.stdout") != native_exec["stdout_sha256"]:
            raise ValueError("native log differs from execution receipt")
        if native["project"]["complete"] != (native_exec["exit_code"] == 0):
            raise ValueError("native completion differs from execution receipt")
        result["native"].update(
            {
                "seconds": round(native_exec["seconds"], 3),
                "exit": native_exec["exit_code"],
                "semantic_context": native["parity"]["semantic_context"],
                "incomplete_files": [
                    normalized_path(f["path"])
                    for f in native["project"]["files"]
                    if f["status"] == "failed"
                ],
                "rule_set_violation_count": len(
                    native["parity"]["rule_set_violations"]
                ),
            }
        )
    result["evidence_sha256"] = evidence_digests(folder, native_folder)
    if (folder / "issues.json").is_file():
        reference_issues = read_json(folder / "issues.json")
        result["reference"]["issue_records"] = len(reference_issues)
    if (folder / "hotspots.json").is_file():
        result["reference"]["hotspots"] = len(read_json(folder / "hotspots.json"))
    return row, result, native, reference_issues


def file_scope(folder, native_folder, root, native, result):
    reference_index = source_indexes(folder, root, "reference")
    native_index = source_indexes(native_folder, root, "native")
    shared = reference_index.keys() & native_index.keys()
    if any(reference_index[f] != native_index[f] for f in shared):
        raise ValueError("shared indexed source bytes differ")
    if not shared:
        result["comparison_state"] = "not_compared_no_shared_files"
    else:
        result["comparison_state"] = (
            "same_scope"
            if native_index.keys() == reference_index.keys()
            else "shared_files_only"
        )
    reference_files = read_json(folder / "indexed-files.json")
    result["files"] = {
        "shared": len(shared),
        "native_only": sorted(native_index.keys() - reference_index.keys()),
        "reference_only": sorted(reference_index.keys() - native_index.keys()),
        "reference_by_language": count_tree(
            f.get("language", "no_language") for f in reference_files
        ),
        "native_by_language": count_tree(f["language"] for f in native["files"]),
    }
    return reference_index, reference_files, shared


def finding_comparison(
    folder,
    effective,
    native_catalog,
    infra,
    root,
    native,
    reference_issues,
    row,
    reference_index,
    reference_files,
    shared,
):
    profiles = check_profiles(folder, effective)
    native_active = {
        r["key"]: {
            p["key"]: p["default_value"]
            for p in r["parameters"]
            if p.get("default_value") is not None
        }
        for r in native["parity"]["active_rules"]
    }
    reference_active = {
        key for key, r in profiles.items() if r["type"] != "SECURITY_HOTSPOT"
    }
    declared_shared = native_active.keys() & reference_active
    implemented_shared = declared_shared - infra
    parameters_match = {
        key
        for key in implemented_shared
        if native_active[key] == profiles[key]["parameters"]
    }

    def key_class(key):
        if key not in reference_active:
            return "reference_inactive"
        if key in infra:
            return "native_documented_implementation_gap"
        if key not in native_active:
            return "native_inactive_or_unknown"
        if key not in parameters_match:
            return "shared_parameter_difference"
        return "shared_equal_declared_parameters"

    native_rules, native_messages, native_hotspots, native_invalid = normalize_native(
        native["files"], root, native_catalog, profiles
    )
    sonar_rules, sonar_messages, sonar_project, sonar_unindexed = normalize_reference(
        reference_issues, row["project_key"], reference_index
    )

    raw_compare = by_rule(native_rules, sonar_rules, key_class)
    raw_compare.pop("by_rule")

    # Keep findings on files outside the intersection visible, but out of the
    # claim on common inputs.
    def restrict(issues):
        return Counter(
            {key: value for key, value in issues.items() if key[1] in shared}
        )

    native_shared, sonar_shared = restrict(native_rules), restrict(sonar_rules)
    native_msg_shared, sonar_msg_shared = (
        restrict(native_messages),
        restrict(sonar_messages),
    )
    observed_languages = {f.get("language", "no_language") for f in reference_files}
    relevant_shared_rules = {
        key
        for lang in observed_languages & effective.keys()
        for key in effective[lang]["rules"]
    }
    return {
        "raw_valid_file_issues": raw_compare,
        "shared_files": by_rule(native_shared, sonar_shared, key_class),
        "same_primary_and_message_on_shared_files": sum(
            (native_msg_shared & sonar_msg_shared).values()
        ),
        "outside_common_file_scope": {
            "native": sum(native_rules.values()) - sum(native_shared.values()),
            "reference": sum(sonar_rules.values()) - sum(sonar_shared.values()),
        },
        "not_compared": {
            "native_hotspot_corresponding_findings": sum(native_hotspots.values()),
            "native_invalid_primary_range": sum(native_invalid.values()),
            "reference_project_level_findings": sum(sonar_project.values()),
            "reference_findings_without_measured_file": sum(sonar_unindexed.values()),
        },
        "profile_rules_on_indexed_languages": {
            "declared_active_both": len(declared_shared & relevant_shared_rules),
            "declared_active_both_excluding_documented_native_gaps": len(
                implemented_shared & relevant_shared_rules
            ),
            "shared_implemented_keys_equal_declared_parameters": len(
                parameters_match & relevant_shared_rules
            ),
            "shared_implemented_keys_with_parameter_differences": len(
                (implemented_shared - parameters_match) & relevant_shared_rules
            ),
            "shared_equal_declared_parameters_key_set_sha256": canonical_sha(
                sorted(parameters_match & relevant_shared_rules)
            ),
        },
    }


def summarize_project(folder, effective, native_catalog, infra, native_folder):
    row, result, native, reference_issues = project_metadata(folder, native_folder)
    if (
        result["reference"]["state"] != "complete"
        or result["native"]["status"] != "complete"
    ):
        result["comparison_state"] = "not_compared_incomplete_or_unavailable"
        return result
    root = Path(row["path"]).resolve()
    reference_index, reference_files, shared = file_scope(
        folder, native_folder, root, native, result
    )
    if shared:
        result["findings"] = finding_comparison(
            folder,
            effective,
            native_catalog,
            infra,
            root,
            native,
            reference_issues,
            row,
            reference_index,
            reference_files,
            shared,
        )
        result["metrics"] = metrics_summary(
            folder, native, result["comparison_state"] == "same_scope"
        )
    return result


def verified_boundaries(commit):
    # Java and Ruby have route-local registrations whose documented
    # infrastructure inventory can lag their implemented subsets.
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("native verified commit must be a full SHA")

    def blob(path):
        return subprocess.check_output(
            ["git", "-C", str(REPO), "show", f"{commit}:{path}"]
        )

    infra_blob = blob(INFRA)
    infra = {
        key
        for key, value in json.loads(infra_blob)["boundaries"].items()
        if value["implementation_gap"]
    }
    registrations = {}
    for lang in ("java", "ruby"):
        source = blob(f"crates/hoonarqube-{lang}/src/rules/mod.rs").decode()
        match = re.search(r"const RULE_KEYS:.*?= &\[(.*?)\];", source, re.DOTALL)
        if not match:
            raise ValueError(f"cannot verify {lang} route-local rule registry")
        keys = sorted(set(re.findall(r'"(' + lang + r':S[0-9]+)"', match[1])))
        if not keys:
            raise ValueError(f"{lang} route-local rule registry is empty")
        registrations[lang] = keys
        infra.difference_update(keys)
    return infra, hashlib.sha256(infra_blob).hexdigest(), registrations


def collect_projects(
    state,
    native_root,
    native_replay,
    environment,
    original_binary,
    effective,
    catalog,
    infra,
):
    projects = {}
    for location in ("pilot", "captures", "additional", "aligned"):
        group = state / location
        if not group.exists():
            continue
        if read_json(group / "native-binary.json") != original_binary:
            raise ValueError(f"{location} native binary differs")
        current_env = read_json(group / "reference-environment.json")
        for key in ("server", "plugins", "server_image", "scanner_image"):
            if current_env[key] != environment[key]:
                raise ValueError(f"{location} reference environment differs at {key}")
        for folder in sorted(path.parent for path in group.glob("*/progress.json")):
            if folder.name in projects:
                raise ValueError(f"duplicate {folder.name} evidence")
            try:
                native_folder = native_root / folder.name if native_replay else folder
                if not (native_folder / "progress.json").exists():
                    raise ValueError("no native replay for expected row")
                row = summarize_project(
                    folder, effective, catalog, infra, native_folder
                )
            except Exception as error:  # noqa: BLE001 - preserve a failed evidence row
                print(f"{folder.name}: {error}", flush=True)
                row = {"comparison_state": "evidence_validation_failed"}
            projects[folder.name] = row

    return projects


def read_project_inventory(state, projects):
    documented_projects = {}
    for file in (
        state / "projects.json",
        state / "projects-additional-ready.json",
        state / "projects-aligned.json",
    ):
        if file.is_file():
            for row in read_json(file):
                documented_projects[row["name"]] = {
                    k: row[k]
                    for k in (
                        "repository",
                        "ref",
                        "commit",
                        "tree",
                        "sources",
                        "exclude",
                        "language",
                    )
                }
    for name in documented_projects.keys() - projects.keys():
        projects[name] = {"comparison_state": "capture_pending_or_unavailable"}
    return documented_projects


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--native-verified-commit", required=True)
    parser.add_argument("--native-replay", type=Path)
    args = parser.parse_args()
    state = args.state.resolve()
    environment = read_json(state / "pilot/reference-environment.json")
    context = read_json(state / "profiles/effective.json")
    native_root = args.native_replay.resolve() if args.native_replay else state
    catalog = {
        r["external_key"]: r["rule_type"]
        for r in read_json(native_root / "native-rule-catalog.json")
    }
    infra, infra_sha, registered = verified_boundaries(args.native_verified_commit)
    original_binary = read_json(state / "pilot/native-binary.json")
    binary = (
        read_json(native_root / "native-binary.json")
        if args.native_replay
        else original_binary
    )
    projects = collect_projects(
        state,
        native_root,
        args.native_replay,
        environment,
        original_binary,
        context["profiles"],
        catalog,
        infra,
    )
    documented_projects = read_project_inventory(state, projects)
    summary = {
        "schema_version": JSON_FORMAT_VERSION,
        "method": "Live selected public source scopes; primary issue identities use rule, relative file and UTF-16 range.",
        "native": {
            "verified_code": args.native_verified_commit,
            "version": binary["version"],
            "sha256": binary["sha256"],
            "profile": "sonar-parity",
            "infrastructure_boundaries_sha256": infra_sha,
            "verified_route_local_keys": registered,
        },
        "sonarqube": {
            "edition": environment["navigation"]["edition"],
            "version": environment["server"]["version"],
            "server_image": environment["server_image"],
            "scanner_image": environment["scanner_image"],
            "embedded_database": not environment["navigation"]["productionDatabase"],
            "plugins": [
                {
                    k: r[k]
                    for k in ("key", "version", "implementationBuild", "hash")
                    if k in r
                }
                for r in environment["plugins"]["plugins"]
            ],
            "rule_profiles": {
                lang: {
                    "name": profile["name"],
                    "builtin": profile["builtin"],
                    "default": profile["default"],
                    "active_rules": len(profile["rules"]),
                    "type_scope_effective_parameters_sha256": canonical_sha(
                        profile["rules"]
                    ),
                }
                for lang, profile in context["profiles"].items()
            },
        },
        "campaign_states": count_tree(
            row["comparison_state"] for row in projects.values()
        ),
        "projects": {
            name: (
                {"selected": documented_projects.get(name), **row}
                if "source" not in row
                else row
            )
            for name, row in sorted(projects.items())
        },
    }
    write_json_atomic(args.output, summary)
    print(summary["campaign_states"], flush=True)


if __name__ == "__main__":
    main()
