#!/usr/bin/env python3
"""Replay five public new-code duplication gates against captured Community results."""

import argparse
import json
import math
import re
import subprocess
import tempfile
from pathlib import Path

from community_duplication_reference import (
    GATES,
    IDS,
    RECEIPT,
    SCANNER,
    SERVER,
    capture_reference,
    check,
    read,
    sha,
)
from public_corpus_prepare import GIT_ENV

REPOS = {"yjs": "yjs/yjs", "fastapi": "fastapi/fastapi"}
CONFIG = {
    "metric": "duplicated_lines_density",
    "scope": "new_code",
    "operator": "lte",
    "threshold": 3,
    "small_change_policy": "community20",
}


def git(root, *args):
    return subprocess.check_output(
        ["git", "-c", "core.hooksPath=/dev/null", *args],
        cwd=root,
        env=GIT_ENV,
        timeout=240,
    )


def checkout(work, repo, local, cases):
    stage = work / repo
    if local:
        git(
            work,
            "clone",
            "-q",
            "--local",
            "--no-checkout",
            "--",
            str(local.resolve(strict=True)),
            str(stage),
        )
    else:
        git(work, "init", "-q", str(stage))
        git(stage, "remote", "add", "origin", f"https://github.com/{REPOS[repo]}.git")
        git(stage, "config", "remote.origin.promisor", "true")
        git(stage, "config", "remote.origin.partialclonefilter", "blob:none")
        revisions = sorted(
            {c[s]["revision"] for c in cases for s in ("base", "candidate")}
        )
        git(
            stage,
            "fetch",
            "-q",
            "--no-tags",
            "--filter=blob:none",
            "--depth=128",
            "origin",
            *revisions,
        )
    git(
        stage,
        "sparse-checkout",
        "set",
        "--no-cone",
        *sorted({"/" + c["path"] for c in cases}),
    )
    return stage


def prepare(root, path, pin):
    rev = pin["revision"]
    git(root, "checkout", "-q", "--detach", rev)
    check(
        git(root, "rev-parse", "HEAD", "HEAD^{tree}", f"HEAD:{path}")
        .decode()
        .splitlines()
        == [rev, pin["tree"], pin["blob"]],
        "wrong commit, tree or blob",
    )
    content = (root / path).read_bytes()
    check(
        sha(content) == pin["sha256"]
        and content == git(root, "cat-file", "blob", pin["blob"]),
        "source bytes differ from captured Git object",
    )
    return content


def changed_lines(root, path, base, candidate):
    git(root, "merge-base", "--is-ancestor", base, candidate)
    diff = git(
        root,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--no-color",
        "-U0",
        base,
        candidate,
        "--",
        path,
    )
    lines = set()
    for m in re.finditer(
        rb"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", diff, re.MULTILINE
    ):
        first = int(m[1])
        lines.update(range(first, first + int(m[2] or 1)))
    return lines


def native_scan(cli, root, path, args):
    cmd = [cli, "analyze", path, "--profile", "sonar-parity", "--format", "json", *args]
    proc = subprocess.run(cmd, cwd=root, capture_output=True, timeout=180, check=False)
    check(
        proc.returncode in (0, 1, 2) and proc.stdout,
        f"native scanner did not return a report (exit {proc.returncode})",
    )
    return proc.returncode, json.loads(proc.stdout)


def inventory(report, path, revision):
    project = report["project"]
    (file,) = project["files"]
    check(
        project["complete"]
        and file["status"] == "complete"
        and file["path"] == path
        and [f["path"] for f in report["files"]] == [path],
        "incomplete or unscoped native inventory",
    )
    check(
        report["assessment"]["context"]["source_revision"] == revision
        and [s["path"] for s in report["assessment"]["sources"]] == [path],
        "wrong native source revision or inventory",
    )


def duplicate_lines(report, path):
    duplicate = set()
    for group in report["project"]["duplications"]:
        for occurrence in group["occurrences"]:
            first, last = occurrence["start_line"], occurrence["end_line"]
            check(
                occurrence["path"] == path
                and 0
                < first
                <= last
                <= report["project"]["files"][0]["metrics"]["lines"],
                "invalid duplication occurrence",
            )
            if not occurrence.get("relation_only", False):
                duplicate.update(range(first, last + 1))
    return duplicate


def native_result(report, code, case, changed):
    new = report["assessment"]["new_code"]
    check(
        new["reference_context"]["source_revision"] == case["base"]["revision"],
        "native baseline is unbound",
    )
    gate = report["assessment"]["gate"]
    (cond,) = gate["conditions"]
    check(
        all(cond[k] == v for k, v in CONFIG.items())
        and gate["status"] == cond["status"],
        "unexpected native gate",
    )
    if case["project"].endswith(IDS["yjs"][0]):
        check(
            new["status"] == "incomplete"
            and code == 2
            and gate["status"] == "unavailable"
            and cond["actual"] is None
            and "ignored_on_small_change" not in cond
            and "changed_source_lines" not in new
            and any("ambiguous baseline line mapping" in m for m in new["diagnostics"]),
            "ambiguous source must be unavailable",
        )
        return {
            "new": None,
            "duplicated": None,
            "density": None,
            "status": "unavailable",
            "ignored": False,
            "exit": 2,
        }
    (entry,) = new["changed_source_lines"]
    check(
        new["status"] == "complete"
        and entry["path"] == case["path"]
        and entry["lines"] == sorted(changed),
        "native changed lines differ from Git",
    )
    total = len(changed)
    duplicates = len(duplicate_lines(report, case["path"]) & changed)
    ratio = 100 * duplicates / total
    ignored = ratio > 3 and total < 20
    expected = "fail" if ratio > 3 and not ignored else "pass"
    check(
        cond.get("ignored_on_small_change") == (total if ignored else None)
        and expected == cond["status"]
        and code == int(expected == "fail")
        and cond["actual"] is not None
        and math.isclose(cond["actual"], ratio),
        "native gate or exception differs from counted occurrences",
    )
    return {
        "new": total,
        "duplicated": duplicates,
        "density": round(ratio, 6),
        "status": expected,
        "ignored": ignored,
        "exit": code,
    }


def replay_case(cli, root, case, work):
    path = case["path"]
    base = case["base"]["revision"]
    candidate = case["candidate"]["revision"]
    changed = changed_lines(root, path, base, candidate)
    check(
        len(changed) == case["reference"]["new"],
        "Git physical changes differ from reference new lines",
    )
    prepare(root, path, case["base"])
    code, baseline = native_scan(cli, root, path, ["--assessment"])
    inventory(baseline, path, base)
    check(code == 0, "native baseline failed")
    baseline_path = work / "baseline.json"
    baseline_path.write_text(json.dumps(baseline))
    prepare(root, path, case["candidate"])
    code, result = native_scan(
        cli,
        root,
        path,
        ["--baseline", str(baseline_path), "--quality-gate", str(work / "gate.json")],
    )
    inventory(result, path, candidate)
    value = native_result(result, code, case, changed)
    if value["status"] == "unavailable":
        # The pinned ambiguous Yjs case must still fail closed.
        check(value == case["native"], "unexpected unavailable gate")
    else:
        ref = case["reference"]
        check(
            value["new"] == ref["new"]
            and value["duplicated"] == ref["duplicated"]
            and value["ignored"] == ref["ignored"]
            and value["exit"] == int(ref["status"] == "ERROR"),
            "native measurements or decision differ from Community",
        )
    return {
        "project": case["project"],
        "git_new_lines": len(changed),
        "reference": case["reference"],
        "native": value,
    }


def validate_cases(data):
    check(
        data["server"] == SERVER and data["scanner"] == SCANNER,
        "wrong reference release",
    )
    cases = data["cases"]
    expected = {
        f"hq-{repo}-duplication-20261122-{i}" for repo, ids in IDS.items() for i in ids
    }
    check(
        {c["project"] for c in cases} == expected and len(cases) == len(expected),
        "five distinct verified cases required",
    )
    tasks = [
        c[s][key]
        for c in cases
        for s in ("base", "candidate")
        for key in ("computeId", "analysisId")
    ]
    check(
        len(set(tasks)) == 20 and all(re.fullmatch(r"[a-f0-9-]{36}", t) for t in tasks),
        "missing or reused analysis or task",
    )
    for case in cases:
        verify_case(case)
    check(
        any(
            c["native"]["ignored"]
            and c["reference"]["ignored"]
            and min(c["native"]["density"], c["reference"]["density"]) > 3
            for c in cases
        ),
        "missing a real suppressed exceedance",
    )
    return cases


def verify_case(case):
    repo = case["repo"]
    path = case["path"]
    tags = (
        sha(path.encode())[:6],
        case["base"]["revision"][:8],
        case["candidate"]["revision"][:8],
    )
    check(
        repo in REPOS
        and "-".join(tags) in IDS[repo]
        and case["project"] == f"hq-{repo}-duplication-20261122-" + "-".join(tags),
        "unexpected project, path or revision",
    )
    check(
        case["period"] == case["base"]["analysisId"]
        and case["gate"] == GATES[repo]
        and case["assignment_default"] is False
        and (case["period_type"], case["period_branch"])
        == ("SPECIFIC_ANALYSIS", "main"),
        "invalid specific-analysis period or gate assignment",
    )
    for stage in ("base", "candidate"):
        pin = case[stage]
        check(pin["ce_status"] == "SUCCESS", "unsuccessful compute task")
        check(
            all(
                re.fullmatch("[a-f0-9]{40}", pin[k])
                for k in ("revision", "tree", "blob")
            )
            and re.fullmatch("[a-f0-9]{64}", pin["sha256"]),
            "invalid Git/source pins",
        )
    # This capture pins observed differences as well as agreements.
    ref = case["reference"]
    total = ref["new"]
    value = ref["duplicated"]
    check(
        0 <= value <= total
        and total > 0
        and math.isclose(ref["density"], 100 * value / total, abs_tol=0.00005),
        "incorrect reference counters",
    )
    ignored = ref["density"] > 3 and total < 20
    check(
        ref["ignored"] is ignored
        and ref["status"] == ("ERROR" if ref["density"] > 3 and not ignored else "OK"),
        "incorrect reference verdict",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bin_dir", type=Path)
    parser.add_argument("--yjs-repository", type=Path)
    parser.add_argument("--fastapi-repository", type=Path)
    parser.add_argument(
        "--capture-root",
        type=Path,
        help="revalidate original Community capture files before replay",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    cases = validate_cases(read(RECEIPT))
    cli = (args.bin_dir / "hoonarqube").resolve(strict=True)
    if args.capture_root:
        check(
            capture_reference(args.capture_root)
            == [{k: v for k, v in c.items() if k != "native"} for c in cases],
            "raw responses differ from published receipt",
        )
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        (work / "gate.json").write_text(
            json.dumps({"schema_version": 1, "conditions": [CONFIG]})
        )
        for repo, local in (
            ("yjs", args.yjs_repository),
            ("fastapi", args.fastapi_repository),
        ):
            selected = [c for c in cases if c["repo"] == repo]
            root = checkout(work, repo, local, selected)
            results.extend(replay_case(cli, root, c, work) for c in selected)
    output = json.dumps({"cases": results}, indent=2) + "\n"
    if args.output:
        args.output.write_text(output)
    print(output, end="")


if __name__ == "__main__":
    main()
