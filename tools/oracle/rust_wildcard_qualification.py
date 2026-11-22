"""Verify scoped native, integrated Clippy and external Clippy results from a captured run."""

import argparse
from collections import Counter
import hashlib
import json
import re
from pathlib import Path
import subprocess

from public_corpus_summary import (
    normalize_native,
    normalize_reference,
    utf16_coordinates,
)

RULE = "rust:S2208"
EXTERNAL = "external_clippy:wildcard_imports"
LINT = "clippy::wildcard_imports"
CASES = ("clap", "hashbrown", "indexmap", "log", "memchr", "rayon", "serde-json")


def read(path):
    return json.loads(path.read_bytes())


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require(check, message):
    if not check:
        raise ValueError(message)


def environment(captures):
    path = captures / "environment.json"
    # Pins the complete independent environment capture, including image, CLI
    # and plugin digests, the compiler host, and the plugin's Clippy mapping.
    require(
        digest(path)
        == "9f3721a8e2e17042d488469ca1a391d7c0b4b0026e439c5f772826d0be3dfd2c",
        "unexpected reference toolchain or mapping",
    )
    return read(path)


def scanner_evidence(case, mode, task):
    work = case / mode
    commit = read(case / "revision.json")["commit"]
    expected = dict(
        flag.removeprefix("-D").split("=", 1)
        for flag in read(case / "scope-flags.json")
    )
    expected.update(
        {
            "sonar.projectKey": task["componentKey"],
            "sonar.projectVersion": commit,
            "sonar.scm.revision": commit,
            "sonar.rust.clippy.enabled": str(mode == "integrated").lower(),
            "sonar.rust.clippy.offline": "true",
            "sonar.rust.clippyReport.reportPaths": f"cases/{case.name}/integrated/clippy.jsonl"
            if mode == "external"
            else "",
        }
    )
    require(
        read(work / "scanner-settings.json") == expected,
        "unexpected compute task scanner settings",
    )
    log = (work / "scanner.log").read_bytes()
    base = re.search(rb"(?m) INFO  Base dir: ([^\r\n]+)/cases/[^/]+/source$", log)
    require(
        base and task["id"].encode() in log, "scanner log does not identify this task"
    )
    require(
        (b"Sensor Clippy [rust]" in log) == (mode == "integrated"),
        "unexpected Clippy sensor",
    )
    # Replace only the local qualification directory, keeping the file portable.
    return hashlib.sha256(log.replace(base[1], b"<qualification>")).hexdigest()


def scoped(values, rule):
    return Counter({k[1:]: v for k, v in values.items() if k[0] == rule})


def native_ranges(case, name, inventory):
    report = read(case / name)
    files = report["files"]
    require(
        report["project"]["complete"]
        and len(files) == len(inventory)
        and {f["path"] for f in files} == set(inventory),
        "native scope mismatch",
    )
    ordinary, _, _, invalid = normalize_native(files, case / "source", {}, {})
    require(not scoped(invalid, RULE), "invalid native range")
    return scoped(ordinary, RULE)


def clippy_ranges(case, mode, inventory):
    work = case / mode
    execution = read(work / "clippy-exec.json")
    require(
        execution["exit"] == 0 and execution["cwd"] == ".",
        "unsuccessful Clippy execution",
    )
    require(
        any(LINT in a for a in execution["args"]) and "--offline" in execution["args"],
        "missing offline wildcard analysis",
    )
    values = Counter()
    outside = 0
    for raw in (work / "clippy.jsonl").read_bytes().splitlines():
        msg = json.loads(raw).get("message") or {}
        if (msg.get("code") or {}).get("code") != LINT:
            continue
        for span in msg["spans"]:
            if not span["is_primary"]:
                continue
            path = span["file_name"]
            if path not in inventory:
                outside += 1
                continue
            lines = (case / "source" / path).read_text().splitlines()
            pos = {
                k: {"line": span[f"line_{k}"], "column": span[f"column_{k}"] - 1}
                for k in ("start", "end")
            }
            values[(path, *utf16_coordinates({"range": pos}, lines))] += 1
    return values, outside


def reference(case, mode, inventory):
    work = case / mode
    task = read(work / "analysis.json")
    require(
        task["type"] == "REPORT" and task["status"] == "SUCCESS",
        "incomplete compute task",
    )
    key = task["componentKey"]
    require(key == f"hq-s2208-20261122-{case.name}-{mode}", "wrong project")
    history = read(work / "history.json")["analyses"]
    require(
        len(history) == 1
        and history[0]["key"] == task["analysisId"]
        and history[0]["revision"] == read(case / "revision.json")["commit"],
        "wrong bound source revision",
    )
    files = read(work / "files.json")
    require(
        len(files) == len(inventory) and {r["path"] for r in files} == set(inventory),
        "reference scope mismatch",
    )
    profile = read(work / "profile.json")
    require(
        len(profile) == 1
        and profile[0]["name"] == "Sonar way"
        and profile[0]["isBuiltIn"],
        "wrong Rust quality profile",
    )
    ordinary, _, projects, missing = normalize_reference(
        read(work / "issues.json"), key, inventory
    )
    rule, absent = (RULE, EXTERNAL) if mode == "integrated" else (EXTERNAL, RULE)
    require(
        not (projects[rule] or projects[absent])
        and not (scoped(missing, rule) or scoped(missing, absent))
        and not scoped(ordinary, absent),
        "mixed or unscoped rule",
    )
    return scoped(ordinary, rule), {
        "portable_scanner_log_sha256": scanner_evidence(case, mode, task),
        "task": task["id"],
        "analysis": task["analysisId"],
        "project": key,
        "sha256": {
            f: digest(work / f)
            for f in (
                "analysis.json",
                "issues.json",
                "files.json",
                "profile.json",
                "history.json",
                "scanner-settings.json",
            )
        },
    }


def run_candidate(binary, case, paths):
    result = subprocess.run(
        [binary, "analyze", "--json", "--profile", "sonar-parity", *sorted(paths)],
        cwd=case / "source",
        capture_output=True,
        check=True,
        timeout=300,
    )
    (case / "native-after.json").write_bytes(result.stdout)


def counts(native, expected):
    return {
        "matched": (native & expected).total(),
        "native_only": (native - expected).total(),
        "reference_only": (expected - native).total(),
    }


def frozen_sources(case, frozen):
    require(
        frozen["state"] == "same_scope"
        and read(case / "revision.json") == {k: frozen[k] for k in ("commit", "tree")},
        "wrong public source revision",
    )
    for path, field in (
        ("scope.json", "reference-source-files.json"),
        ("native-before.json", "native.stdout"),
    ):
        require(
            digest(case / path) == frozen["capture_sha256"][field],
            f"{case.name}: changed {path}",
        )


def qualify(case, candidate, run, frozen):
    frozen_sources(case, frozen)
    scope = read(case / "scope.json")
    inventory = {f["path"]: f["sha256"] for f in scope}
    require(
        len(scope) == len(inventory)
        and all(digest(case / "source" / p) == v for p, v in inventory.items()),
        "changed source bytes",
    )
    lock = case / "source/Cargo.lock"
    if case.name != "clap":
        require(
            digest(lock)
            == digest(
                Path(__file__).parent / "rust-wildcard-locks" / (case.name + ".lock")
            ),
            "wrong dependency lock",
        )
    if run:
        run_candidate(candidate, case, inventory)
    before = native_ranges(case, "native-before.json", inventory)
    after = native_ranges(case, "native-after.json", inventory)
    integrated, first = reference(case, "integrated", inventory)
    external, second = reference(case, "external", inventory)
    raw, outside = clippy_ranges(case, "integrated", inventory)
    independent, _ = clippy_ranges(case, "direct", inventory)
    require(
        first["task"] != second["task"] and first["analysis"] != second["analysis"],
        "reused reference analysis",
    )
    require(
        integrated == external == raw == independent,
        "import, integrated or direct ranges differ",
    )
    return {
        "revision": read(case / "revision.json"),
        "files": len(inventory),
        "scanner_scope": read(case / "scope-flags.json"),
        "before": counts(before, integrated),
        "after": counts(after, integrated),
        "integrated": first,
        "external": second,
        "direct_clippy_sha256": digest(case / "direct/clippy.jsonl"),
        "direct_exec_sha256": digest(case / "direct/clippy-exec.json"),
        "clippy_in_scope": raw.total(),
        "clippy_out_of_scope": outside,
        "scope_sha256": digest(case / "scope.json"),
        "cargo_lock_sha256": digest(lock),
        "native_before_sha256": digest(case / "native-before.json"),
        "native_after_sha256": digest(case / "native-after.json"),
        "clippy_report_sha256": digest(case / "integrated/clippy.jsonl"),
        "clippy_exec_sha256": digest(case / "integrated/clippy-exec.json"),
        "after_native_only_ranges": sorted((after - integrated).elements()),
        "after_reference_only_ranges": sorted((integrated - after).elements()),
        "supplemental": supplements(case, inventory, after),
    }


def supplements(case, inventory, native):
    modes = {
        "log": ["kv-std", "kv-tests"],
        "indexmap": ["tests"],
        "rayon": ["tests"],
        "serde-json": ["float-roundtrip", "force-float"],
        "clap": ["tests"],
        "memchr": ["all-targets"],
    }
    out = {}
    for mode in modes.get(case.name, []):
        values, extra = clippy_ranges(case, mode, inventory)
        job = case / mode
        out[mode] = {
            "arguments": read(job / "clippy-exec.json")["args"],
            "clippy_in_scope": values.total(),
            "outside_scope": extra,
            "matched_native": (values & native).total(),
            "report_sha256": digest(job / "clippy.jsonl"),
        }
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--captures", type=Path, required=True)
    p.add_argument(
        "--candidate", type=Path, help="executable to use for a fresh native scan"
    )
    p.add_argument("--run-candidate", action="store_true")
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    if args.run_candidate != bool(args.candidate):
        p.error("provide --candidate and --run-candidate together")
    binary = args.candidate.resolve(strict=True) if args.candidate else None
    publication = read(
        Path(__file__).resolve().parents[2]
        / "docs/engineering/public-projects-2026-11-21.json"
    )
    previous = {
        c["name"]: c
        for wave in publication["waves"].values()
        for c in wave["cases"]
        if c["name"] in CASES
    }
    data = {
        name: qualify(args.captures / name, binary, args.run_candidate, previous[name])
        for name in CASES
    }
    total = {
        phase: {
            key: sum(row[phase][key] for row in data.values())
            for key in ("matched", "native_only", "reference_only")
        }
        for phase in ("before", "after")
    }
    receipt = {
        "environment": environment(args.captures),
        "native_binary_sha256": digest(binary)
        if binary
        else (args.captures / "native-binary.sha256").read_text().strip(),
        "totals": total,
        "projects": data,
    }
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(total))


if __name__ == "__main__":
    main()
