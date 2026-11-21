#!/usr/bin/env python3
"""Rebuild the small pinned contracts from archived Sonar and qualified CLI captures."""

import argparse
import json
from pathlib import Path
import re
import subprocess

from public_contract import MANIFEST, compare, require, validate
import public_corpus_summary as corpus

# Explicit selection. Never silently replace a broken contract with an easier project.
SELECTION = {
    "corpus": ["commander", "commons-cli", "javapoet", "sinatra"],
    "wave2": [
        "async-lru",
        "bytes",
        "commons-csv",
        "cron",
        "floating-ui",
        "httparty",
        "itsdangerous",
        "java-diff-utils",
        "ripgrep",
        "websocket",
    ],
    "wave3": [
        "backoff",
        "express",
        "faraday",
        "fsnotify",
        "iniconfig",
        "koa",
        "markupsafe",
        "minimist",
        "rust-semver",
        "ryu",
        "superstruct",
    ],
}
REFERENCE = "26.9.0.129388"


def read(path):
    return json.loads(path.read_bytes())


def js_sensor(log, file_count):
    blocks = re.findall(
        rf"{corpus.JS_SENSOR}$\n(.*?){corpus.JS_SENSOR} \(done\)", log, re.M | re.S
    )
    require(
        len(blocks) == 1 and corpus.javascript_bundle_evidence(log) is None,
        "ambiguous JS sensor scope",
    )
    counts = re.findall(
        r"\b(\d+)/(\d+) source files? (?:has|have) been analyzed$", blocks[0], re.M
    )
    require(
        counts == [(str(file_count), str(file_count))],
        "JS sensor count differs from source inventory",
    )
    return file_count


def captured_issues(ref):
    """Check pagination against the retained API responses before taking locations."""
    issues = read(ref / "issues.json")
    paths = sorted(
        ref.glob("issues-page-*.json"), key=lambda p: int(p.stem.rsplit("-", 1)[1])
    )
    collected = []
    for index, path in enumerate(paths, 1):
        page = read(path)
        require(
            page["paging"]["pageIndex"] == index
            and page["paging"]["total"] == len(issues),
            "wrong reference issue pagination",
        )
        collected.extend(page["issues"])
    require(
        collected == issues and len({i["key"] for i in issues}) == len(issues),
        "reference issue records are incomplete or duplicated",
    )
    return issues


def capture(suite, measured, name, profiles, catalog, infra, qualified, binding):
    matches = [
        suite / kind / name
        for kind in ("pilot", "captures", "additional", "aligned")
        if (suite / kind / name / "source.json").is_file()
    ]
    require(len(matches) == 1, f"{name}: ambiguous reference capture")
    ref, replay = matches[0], measured / name
    row = read(replay / "source.json")
    src = Path(row["path"]).resolve()
    require(
        read(replay / "binding.json") == binding,
        f"{name}: unexpected qualification binding",
    )
    summary = corpus.summarize_project(ref, profiles, catalog, infra, replay)
    require(
        summary["comparison_state"] == qualified["state"] == "same_scope",
        f"{name}: different source scope",
    )
    files = corpus.source_indexes(ref, src, "reference")
    require(
        files == corpus.source_indexes(replay, src, "native")
        and len(files) == qualified["files"]
        and len(files) <= 35,
        f"{name}: source inventory mismatch",
    )
    components = read(ref / "indexed-files.json")
    require(
        sorted(f["path"] for f in components) == sorted(files),
        f"{name}: unexpected Sonar components",
    )
    ce = read(ref / "compute-engine.json")["task"]
    require(
        ce["status"] == "SUCCESS"
        and ce["componentKey"] == row["project_key"]
        and ce["id"] == qualified["reference_compute_task"]
        and ce["analysisId"] == qualified["reference_analysis_id"],
        f"{name}: wrong Sonar analysis",
    )
    for source_key, case_key in [
        ("commit", "commit"),
        ("tree", "tree"),
        ("repository", "repository"),
        ("sources", "roots"),
        ("exclude", "exclusions"),
    ]:
        require(
            row[source_key] == qualified[case_key], f"{name}: different {source_key}"
        )
    log = (ref / "scanner.stdout").read_text()
    require(
        f"Communicating with SonarQube Community Build {REFERENCE}\n" in log,
        f"{name}: wrong reference server",
    )
    receipt = {
        "project_key": ce["componentKey"],
        "compute_task": ce["id"],
        "analysis_id": ce["analysisId"],
        "issues_sha256": corpus.digest(ref / "issues.json"),
        "scanner_log_sha256": corpus.digest(ref / "scanner.stdout"),
        "native_stdout_sha256": corpus.digest(replay / "native.stdout"),
    }
    require(
        receipt["issues_sha256"] == qualified["reference_issue_digest"]
        and receipt["native_stdout_sha256"] == qualified["native_report_digest"],
        f"{name}: wrong captured issue/report digest",
    )
    if row["language"] in {"js", "ts"}:
        require(
            all(f["language"] in {"js", "ts"} for f in components),
            f"{name}: mixed JS scope",
        )
        receipt["js_sensor_analyzed"] = js_sensor(log, len(files))
    if row["language"] == "java":
        receipt["java_release"] = row["java_release"]
        receipt["java_context_sha256"] = row["java_context_sha256"]
    reference, _, project_issues, unindexed = corpus.normalize_reference(
        captured_issues(ref), row["project_key"], files
    )
    effective = corpus.check_profiles(ref, profiles)
    native = read(replay / "native.stdout")
    require(
        native == read(replay / "native.json"),
        f"{name}: native JSON differs from stdout",
    )
    _, _, hotspots, invalid = corpus.normalize_native(
        native["files"], src, catalog, effective
    )
    exclude_rules = (
        set(project_issues)
        | set(hotspots)
        | {k for k, _ in unindexed}
        | {k for k, _ in invalid}
    )
    exclude_rules.update(k for k, _, sl, *_ in reference if sl is None)
    by_rule = summary["findings"]["shared_files"]["by_rule"]
    rules = {
        k: effective[k]["parameters"]
        for k, r in sorted(by_rule.items())
        if k not in exclude_rules
        and r["class"] == "shared_equal_declared_parameters"
        and r.get("matched", 0) > 0
        and r.get("native_only", 0) == r.get("reference_only", 0) == 0
    }
    primaries = sorted(
        list(identity) for identity in reference.elements() if identity[0] in rules
    )
    case = {
        "name": name,
        "campaign": suite.name,
        "language": row["language"],
        "repository": row["repository"],
        "commit": row["commit"],
        "tree": row["tree"],
        "sources": row["sources"],
        "exclude": row["exclude"],
        "source_inventory_sha256": corpus.canonical_sha(files),
        "files": dict(sorted(files.items())),
        "semantic_context": native["parity"]["semantic_context"],
        "reference": receipt,
        "parameters": rules,
        "primaries": primaries,
    }
    validate(case)
    compare(case, native, src)
    return case


def generate(captures, qualified, retained):
    provenance = read(retained / "receipt.json")
    binary = retained / "hoonarqube"
    binding = {
        "head": provenance["head"],
        "tree": provenance["tree"],
        "binary": corpus.digest(binary),
    }
    require(
        binding["binary"] == provenance["binaries"]["hoonarqube"],
        "wrong retained executable",
    )
    infra, infra_hash, _ = corpus.verified_boundaries(binding["head"])
    catalog = {
        r["external_key"]: r["rule_type"]
        for r in json.loads(
            subprocess.check_output([binary, "rules", "list", "--json"])
        )
    }
    projects = []
    for campaign, names in SELECTION.items():
        suite, replay = captures / campaign, qualified / campaign
        profiles = read(suite / "profiles/effective.json")["profiles"]
        measured = read(replay / "verified.json")
        require(
            (
                measured["native_commit"],
                measured["native_tree"],
                measured["native_binary_sha256"],
                measured["infra_sha256"],
            )
            == (binding["head"], binding["tree"], binding["binary"], infra_hash),
            f"{campaign}: wrong measured revision",
        )
        projects.extend(
            capture(
                suite,
                replay,
                name,
                profiles,
                catalog,
                infra,
                measured["cases"][name],
                binding,
            )
            for name in names
        )
    return {
        "format": 1,
        "reference_community_build": REFERENCE,
        "qualified_native": binding,
        "projects": projects,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--captures", type=Path, required=True)
    parser.add_argument("--qualified", type=Path, required=True)
    parser.add_argument("--retained", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the complete manifest against the archives",
    )
    args = parser.parse_args()
    result = generate(args.captures, args.qualified, args.retained)
    if args.check:
        require(
            read(args.manifest) == result,
            "manifest differs from qualified reference capture",
        )
    else:
        # Keep one primary location per line for readable review diffs.
        document = json.dumps(result, ensure_ascii=False, indent=2)
        document = re.sub(
            r'\[\n\s+("[^"\n]+:S\d+"),\n\s+("[^"\n]+"),\n\s+(\d+),\n\s+(\d+),\n\s+(\d+),\n\s+(\d+)\n\s+\]',
            r"[\1, \2, \3, \4, \5, \6]",
            document,
        )
        args.manifest.write_text(document + "\n")
    print(f"Confirmed {len(result['projects'])} captured Sonar project contracts.")


if __name__ == "__main__":
    main()
