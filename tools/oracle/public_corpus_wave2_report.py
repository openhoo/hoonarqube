#!/usr/bin/env python3
"""Validate and package the second public-corpus result and exact source manifest."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

from parity import read_json, write_json_atomic
from public_corpus_capture import verify_checkout
from public_corpus_summary import REPO, canonical_sha, source_indexes
from public_corpus_wave2_capture import BINARY_SHA256, CACHE, NETWORK, PILOT, REFERENCE

BUILT = "9084eeca7eb9350f028fa9a791b1f0f0ca395968"
MAIN = "e43dc65805fdba7c4cd27c1cbfc6f285c717f87d"
TREE = "5d9ccd5cc837d3fb2105172bcbeccb7cfc0866bc"
LANGUAGES = {
    "py": "Python",
    "go": "Go",
    "js": "JavaScript",
    "ts": "TypeScript",
    "rust": "Rust",
    "java": "Java",
    "ruby": "Ruby",
}
TALLY = ("matched", "native_only", "reference_only")
REFERENCE_BLOCKS = {
    "gson": "The Java 8 bridge rejected module-info.java. The project also expects Maven-filtered Java sources.",
    "jsoup": "The isolated compiler could not resolve javax.annotation.Nullable (JSR 305).",
}
NATIVE_BLOCKS = {
    "react-hook-form": (
        "A hash-verified native TypeScript helper appeared under the selected src "
        "root after the scan. The checkout guard rejected the row; its completed "
        "SonarQube scan remains in the receipt."
    ),
}
SOURCE_BLOCKS = {
    "crossbeam-channel": "Tracked symlink crossbeam-channel/src/alloc_helper.rs inside the selected root.",
}


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def manifests(state, summary):
    selected = read_json(state / "projects-planned.json")
    pinned = {r["name"]: r for r in read_json(state / "replay-projects.json")}
    assert len(selected) == len({r["repository"].lower() for r in selected}) == 42
    assert len(pinned) == len(summary["projects"])
    assert {r["name"] for r in selected} >= pinned.keys()
    first = read_json(REPO / "tools/oracle/public-corpus-projects-20261120.json")
    prior = {r["repository"].lower() for rows in first.values() for r in rows}
    assert not prior.intersection(p["repository"].lower() for p in selected)
    source_manifest, preflight = [], {}
    for row in selected:
        name = row["name"]
        if name in pinned:
            observed = pinned[name]
            assert git(observed["path"], "rev-parse", "HEAD") == observed["commit"]
            assert git(observed["path"], "rev-parse", "HEAD^{tree}") == observed["tree"]
            preflight[name] = {"state": "checked_out"}
            if "reference_excluded" in observed:
                preflight[name]["reference_bridge"] = REFERENCE_BLOCKS[name]
        else:
            root = state / "sources" / name
            observed = {
                **row,
                "commit": git(root, "rev-parse", "HEAD"),
                "tree": git(root, "rev-parse", "HEAD^{tree}"),
            }
            preflight[name] = {"state": "scope_rejected", "reason": SOURCE_BLOCKS[name]}
        fields = (
            "name",
            "repository",
            "language",
            "sources",
            "exclude",
            "selection_ref",
            "commit",
            "tree",
            "project_key",
            "java_release",
        )
        source_manifest.append({k: observed[k] for k in fields if k in observed})
    return pinned, {"schema_version": 1, "projects": source_manifest}, preflight


def evidence_audit(state, summary, pinned):
    before = read_json(state / "profiles/effective.json")["profiles"]
    after = read_json(state / "profiles-end/effective.json")["profiles"]
    assert before == after, "effective profile changed"
    assert summary["native"]["sha256"] == BINARY_SHA256
    assert summary["native"]["verified_code"] == MAIN
    assert git(REPO, "rev-parse", f"{BUILT}^{{tree}}") == TREE
    assert git(REPO, "rev-parse", f"{MAIN}^{{tree}}") == TREE
    logs = {
        **read_json(state / "pilot/run-summary.json"),
        **read_json(state / "captures/run-summary.json"),
    }
    assert logs.keys() == pinned.keys()
    for name, row in summary["projects"].items():
        raw = state / ("pilot" if name == PILOT else "captures") / name
        status = logs[name]
        if row["comparison_state"] in {"same_scope", "shared_files_only"}:
            assert "ended_at_utc" in status
            root = verify_checkout(pinned[name])
            sonar_index = source_indexes(raw, root, "reference")
            native_index = source_indexes(raw, root, "native")
            assert all(
                sonar_index[p] == native_index[p]
                for p in sonar_index.keys() & native_index.keys()
            )
            assert (sonar_index.keys() == native_index.keys()) == (
                row["comparison_state"] == "same_scope"
            )
        if row.get("reference", {}).get("state") == "complete":
            assert read_json(raw / "compute-engine.json")["task"]["status"] == "SUCCESS"
    return canonical_sha(before)


def tallies(rows):
    scoped = [r for r in rows if r["comparison_state"] == "same_scope"]
    result = {
        "native_complete": sum(
            r.get("native", {}).get("status") == "complete" for r in rows
        ),
        "reference_complete": sum(
            r.get("reference", {}).get("state") == "complete" for r in rows
        ),
        "identical_file_scopes": len(scoped),
        "identical_scope_files": sum(r["files"]["shared"] for r in scoped),
        "shared_files_only": sum(
            r["comparison_state"] == "shared_files_only" for r in rows
        ),
    }
    for metric in ("aggregate", "duplication"):
        observed = [v for r in scoped for v in r["metrics"][metric].values()]
        result[f"{metric}_matched"] = sum(v["matched"] for v in observed)
        result[f"{metric}_compared"] = len(observed)
    for key, field in (
        ("file_metrics_matched", "matched_cells"),
        ("file_metrics_compared", "compared_cells"),
    ):
        result[key] = sum(r["metrics"]["shared_file_metrics"][field] for r in scoped)
    for label in ("ordinary", "equal_parameters"):
        findings = [
            r["findings"]["shared_files"]
            if label == "ordinary"
            else r["findings"]["shared_files"]["by_class"].get(
                "shared_equal_declared_parameters", {}
            )
            for r in scoped
        ]
        result[label] = {key: sum(f.get(key, 0) for f in findings) for key in TALLY}
    return result


def observation(row):
    names = {
        "same_scope": "Identical files",
        "shared_files_only": "Different file scope",
        "not_compared_incomplete_or_unavailable": "Incomplete or unavailable",
        "not_compared_no_shared_files": "No shared files",
        "evidence_validation_failed": "Evidence validation failed",
        "capture_pending_or_unavailable": "Not captured",
    }
    return names.get(row["comparison_state"], row["comparison_state"])


def boundaries(summary):
    lines = ["", "### Boundaries and failures", ""]
    for name, detail in SOURCE_BLOCKS.items():
        lines.append(f"- **{name}:** {detail} Neither analyzer ran on that scope.")
    for name, detail in REFERENCE_BLOCKS.items():
        lines.append(
            f"- **{name}:** {detail} The native source analysis remains in the receipt."
        )
    for name, detail in NATIVE_BLOCKS.items():
        lines.append(f"- **{name}:** {detail}")
    for name, row in summary["projects"].items():
        native = row.get("native", {})
        if native.get("incomplete_files"):
            files = ", ".join(f"`{f}`" for f in native["incomplete_files"])
            lines.append(
                f"- **{name}:** Native analysis reported incomplete files: {files}."
            )
        if row["comparison_state"] == "shared_files_only":
            files = row["files"]
            lines.append(
                f"- **{name}:** {len(files['native_only'])} native-only and {len(files['reference_only'])} SonarQube-only files. Only the intersection is compared."
            )
        if row.get("reference", {}).get("state") in {"failed", "incomplete"}:
            ref = row["reference"]
            lines.append(
                f"- **{name}:** Reference {ref['state']}. Compute status: {ref.get('compute_status') or 'unavailable'}; parser diagnostic lines: {ref.get('parse_warning_lines') or 0}."
            )
    return lines


def report(out, summary, manifest, preflight, profile_sha):
    overall = tallies(list(summary["projects"].values()))
    audit = {
        "selected_repositories": len(manifest["projects"]),
        "checkout_eligible": len(summary["projects"]),
        "effective_profiles_identical_before_and_after_sha256": profile_sha,
        "native_execution": {
            "built_commit": BUILT,
            "integrated_main": MAIN,
            "tree": TREE,
        },
        "preflight": preflight,
        "native_validation_blocks": NATIVE_BLOCKS,
        "totals_identical_file_scopes": overall,
    }
    write_json_atomic(out / "public-corpus-wave2-projects-20261120.json", manifest)
    write_json_atomic(
        out / "public-corpus-wave2-qualification-20261120.json",
        {**summary, "wave2": audit},
    )
    eq = overall["equal_parameters"]
    all_rules = overall["ordinary"]
    lines = [
        "# Public source comparison with SonarQube, second wave",
        "",
        "November 20, 2026. This extends the first public corpus by selecting 42",
        "different GitHub repositories across the same seven languages. The",
        "[manifest](public-corpus-wave2-projects-20261120.json) records exact commits,",
        "trees, source roots, exclusions, and the analysis keys. The",
        "[receipt](public-corpus-wave2-qualification-20261120.json) records every outcome.",
        "",
        f"Hoonarqube completed **{overall['native_complete']}** scans and SonarQube Community",
        f"Build `{summary['sonarqube']['version']}` completed **{overall['reference_complete']}**.",
        f"Both tools measured **{overall['identical_scope_files']:,}** identical files across",
        f"**{overall['identical_file_scopes']}** identical project scopes. The remaining rows",
        "are visible below and excluded from the whole-scope totals.",
        "",
        "| Observation on identical scopes | Matches or equal | Hoonarqube only | SonarQube only |",
        "| --- | ---: | ---: | ---: |",
        f"| Primary findings on shared rules with matching declared parameters | {eq['matched']:,} | {eq['native_only']:,} | {eq['reference_only']:,} |",
        f"| All valid ordinary primary findings | {all_rules['matched']:,} | {all_rules['native_only']:,} | {all_rules['reference_only']:,} |",
        f"| Project size metric values | {overall['aggregate_matched']:,} / {overall['aggregate_compared']:,} |  |  |",
        f"| File size metric values | {overall['file_metrics_matched']:,} / {overall['file_metrics_compared']:,} |  |  |",
        f"| Duplication metric values | {overall['duplication_matched']:,} / {overall['duplication_compared']:,} |  |  |",
        "",
        "The comparator matches primary findings by rule, relative path and full",
        "UTF-16 range. Supplementary evidence, message or severity equivalence, fixes,",
        "and duplication group equality are outside these totals. A filter for matching",
        "declared rule parameters does not establish detector equivalence.",
        "",
        "## Results by language",
        "",
        "| Language | Selected | Native complete | Reference complete | Identical scopes | Identical files | Matches / native-only / reference-only on shared parameters |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for language, label in LANGUAGES.items():
        intended = [r for r in manifest["projects"] if r["language"] == language]
        selected = [
            summary["projects"][r["name"]]
            for r in intended
            if r["name"] in summary["projects"]
        ]
        counts = tallies(selected)
        findings = counts["equal_parameters"]
        lines.append(
            f"| {label} | {len(intended)} | {counts['native_complete']} | {counts['reference_complete']} | "
            f"{counts['identical_file_scopes']} | {counts['identical_scope_files']:,} | "
            f"{findings['matched']:,} / {findings['native_only']:,} / {findings['reference_only']:,} |"
        )
    lines += [
        "",
        "## Project outcomes",
        "",
        "| Repository | Commit | Native | SonarQube | Comparison | Files in common |",
        "| --- | --- | --- | --- | --- | ---: |",
    ]
    for spec in manifest["projects"]:
        name, repo = spec["name"], spec["repository"]
        row = summary["projects"].get(name)
        if row is None:
            detail = "Source scope rejected"
            n, s, count = "Not run", "Not run", "—"
        else:
            detail = observation(row)
            n = row.get("native", {}).get("status", "Not run")
            s = row.get("reference", {}).get("state", "Not run")
            count = str(row["files"]["shared"]) if "files" in row else "—"
        lines.append(
            f"| {repo} | `{spec['commit'][:12]}` | {n} | {s} | {detail} | {count} |"
        )
    lines += boundaries(summary)
    lines += [
        "",
        "## Provenance and method",
        "",
        f"The executable SHA-256 was `{BINARY_SHA256}`. It was built at",
        f"`{BUILT}`. The fetched `main` commit",
        f"`{MAIN}` had the identical Git tree",
        f"`{TREE}`.",
        "",
        "The reference used the same pinned SonarQube and scanner images as the first",
        "wave, a fresh embedded database and a dedicated internal Docker network.",
        "No package manager, Maven, Gradle, Cargo, or project script ran. Java bridge",
        "classes came from isolated javac invocations with annotation processing disabled.",
        "Rust ran without Clippy. The quality profiles were read live before and after",
        "the corpus; effective values and active keys matched. Per-project quality",
        "profile IDs, rule counts and update markers matched the live pilot. The",
        "scanner ran on an emulated architecture, so the timings do not compare",
        "production throughput. C# project analysis and Enterprise sensors are outside",
        "this qualification.",
        "",
        "## Reproduce",
        "",
        "Use Python 3.11 or newer, a private state directory, and the exact binary.",
        "Set `PYTHONPATH` to the first wave's oracle scripts. Use the image digest",
        "recorded in the receipt to start the reference with the following names:",
        "",
        f"- Container: `{REFERENCE}`.",
        f"- Internal network with alias `reference`: `{NETWORK}`.",
        f"- Scanner cache volume: `{CACHE}`.",
        "- Record the returned container ID in `$state/docker/server.id`.",
        "",
        "Then prepare the pinned sources and isolated Java inputs:",
        "",
        "```sh",
        'python3 public_corpus_wave2_prepare.py --state "$state" --manifest public-corpus-wave2-projects-20261120.json',
        'python3 public_corpus_wave2_prepare.py --state "$state" --java',
        '"$native" rules list --json > "$state/native-rule-catalog.json"',
        'python3 public_corpus_wave2_capture.py --state "$state" --binary "$native" --jobs 1 pilot',
        'python3 public_corpus_wave2_capture.py --state "$state" profiles',
        'python3 public_corpus_wave2_capture.py --state "$state" --binary "$native" --jobs 2 captures',
        "# Record a nonzero capture result and continue with the received rows.",
        'python3 public_corpus_wave2_capture.py --state "$state" profiles-end',
        f'python3 "$PYTHONPATH/public_corpus_summary.py" --state "$state" --native-verified-commit {MAIN} --output "$state/raw-summary.json"',
        'python3 public_corpus_wave2_report.py --state "$state" --summary "$state/raw-summary.json" --out "$state/portable"',
        "```",
        "",
        "The runner refuses new checkouts and scans when fewer than 5 GiB are free.",
        "It retains raw captures in the private state directory.",
        "",
    ]
    (out / "public-corpus-wave2-20261120.md").write_text(
        "\n".join(lines), encoding="utf-8"
    )
    print(overall)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    summary = read_json(args.summary)
    pinned, manifest, preflight = manifests(args.state, summary)
    profile_sha = evidence_audit(args.state, summary, pinned)
    args.out.mkdir(parents=True, exist_ok=True)
    report(args.out, summary, manifest, preflight, profile_sha)


if __name__ == "__main__":
    main()
