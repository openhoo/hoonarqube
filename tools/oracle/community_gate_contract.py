#!/usr/bin/env python3
"""Check production gate decisions against pinned Community analyses without running upstream code."""

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from public_corpus_prepare import GIT_ENV, prepare_checkout
from public_coverage_gate_replay import (
    RECEIPT,
    check,
    scan_coverage_cases,
    verify_uploads,
)

ORACLE = Path(__file__).resolve().parent
DUPLICATION = ORACLE.parents[1] / "docs" / "public-quality-gates-20261120.json"
FIXTURES = ORACLE / "fixtures" / "commander-lcov"
STATUS = {"OK": "pass", "ERROR": "fail"}


def checkout(work, name, row, files, local):
    # The candidate only analyzes data. No packages, hooks or upstream tests are run.
    if local:
        dest = work / "sources" / name
        dest.parent.mkdir(exist_ok=True)
        subprocess.run(
            [
                "git",
                "-c",
                "advice.detachedHead=false",
                "-c",
                "core.hooksPath=/dev/null",
                "clone",
                "-q",
                "--local",
                "--",
                local / name,
                dest,
            ],
            check=True,
            timeout=45,
            env=GIT_ENV,
        )
    root = Path(prepare_checkout(work, {**row, "name": name})["path"])
    for name, digest in files.items():
        path = root / name
        check(
            not Path(name).is_absolute()
            and path.resolve() == path
            and path.is_relative_to(root)
            and path.is_file(),
            f"not a regular source: {name}",
        )
        check(
            hashlib.sha256(path.read_bytes()).hexdigest() == digest,
            f"wrong source: {name}",
        )
    return root


def scope(report, row, files):
    project = report["project"]
    paths = [item["path"] for item in project["files"]]
    check(
        project["complete"] and len(paths) == len(files) and set(paths) == set(files),
        "incomplete or altered file inventory",
    )
    actual = report["parity"]["scope"]
    check(
        actual["roots"] == row["sources"] and actual["exclude"] == row["exclude"],
        "scan scope differs from capture",
    )
    check(
        report["assessment"]["context"]["source_revision"] == row["commit"],
        "wrong analysis revision",
    )


def completed_reference(reference):
    check(
        reference["ce_status"] == "SUCCESS"
        and reference["ce_task_id"]
        and reference["analysis_id"],
        "no completed Community analysis",
    )


def coverage_reference(name, mode, case, report):
    ref = case["reference"]
    completed_reference(ref)
    condition = ref["condition"]
    gate = report["assessment"]["gate"]
    check(len(gate["conditions"]) == 1, "expected one coverage condition")
    actual = gate["conditions"][0]
    check(
        mode in ("full", "one_decimal") and actual.get("precision", "full") == mode,
        "wrong coverage precision",
    )
    threshold = float(condition["errorThreshold"])
    check(
        condition["metricKey"] == actual["metric"] == "line_coverage"
        and condition["comparator"] == "LT"
        and actual["scope"] == "overall"
        and actual["operator"] == "gte"
        and threshold == actual["threshold"],
        "coverage condition differs from reference",
    )
    check(
        ref["gate"] == condition["status"]
        and ref["metrics"]["line_coverage"] == condition["actualValue"],
        "inconsistent Community coverage",
    )
    pct = float(condition["actualValue"])
    want = STATUS[ref["gate"]]
    coverage = report["assessment"].get("coverage")
    eligible = int(ref["metrics"]["lines_to_cover"])
    covered = eligible - int(ref["metrics"]["uncovered_lines"])
    check(0 <= covered <= eligible and eligible > 0, "invalid reference line counts")
    check(
        want == ("pass" if pct >= threshold else "fail"),
        "inconsistent Community coverage verdict",
    )
    if name == "missing":
        check(
            coverage is None
            and covered == 0
            and pct == 0
            and want == "fail"
            and gate["status"] == actual["status"] == "unavailable"
            and actual["actual"] is None,
            "missing LCOV must not become successful or measured zero",
        )
        return
    check(
        coverage["lines"] == {"eligible": eligible, "covered": covered},
        "imported coverage counts differ",
    )
    unrounded = 100 * covered / eligible
    if mode == "full":
        check(
            abs(actual["actual"] - unrounded) < 1e-12
            and float(f"{unrounded:.1f}") == pct,
            "full coverage measurement differs",
        )
        if name == "decimal":
            check(
                want == "pass" and unrounded < threshold == pct,
                "boundary control lost its precision difference",
            )
            want = "fail"
    else:
        check(actual["actual"] == pct, "rounded coverage measurement differs")
    check(
        gate["status"] == actual["status"] == want,
        "coverage verdict differs from Community policy",
    )


def duplication_reference(reference, gate):
    completed_reference(reference)
    ref = reference["projectStatus"]
    check(
        ref["ignoredConditions"] is False and gate["status"] == STATUS[ref["status"]],
        "ignored or changed duplication verdict",
    )
    reference_conditions = {c["metricKey"]: c for c in ref["conditions"]}
    conditions = {c["metric"]: c for c in gate["conditions"]}
    metrics = {"duplicated_lines", "duplicated_lines_density"}
    check(
        len(ref["conditions"]) == len(gate["conditions"]) == 2
        and conditions.keys() == reference_conditions.keys() == metrics,
        "missing or unexpected duplication conditions",
    )
    for key, actual in conditions.items():
        c = reference_conditions[key]
        check(
            c["comparator"] == "GT"
            and c["errorThreshold"] == "0"
            and actual["scope"] == "overall"
            and actual["operator"] == "lte"
            and actual["threshold"] == 0
            and actual["status"] == STATUS[c["status"]],
            f"{key}: duplication condition differs",
        )
        number = actual["actual"]
        if key == "duplicated_lines_density":
            number = float(f"{number:.1f}")
        check(
            number == float(c["actualValue"]), f"{key}: duplication measurement differs"
        )


def replay(work, binaries, local):
    receipt = json.loads(RECEIPT.read_bytes())
    check(
        set(receipt["cases"]) == {"focused", "broad", "decimal", "missing"},
        "expected four Commander captures",
    )
    root = checkout(
        work, "commander", receipt["source"], receipt["source_sha256"], local
    )
    artifacts = root / ".hoonarqube-replay"
    artifacts.mkdir()
    inputs = {}
    for suite in ("focused", "broad"):
        data = gzip.decompress((FIXTURES / f"{suite}.lcov.gz").read_bytes())
        check(
            hashlib.sha256(data).hexdigest() == receipt["cases"][suite]["lcov_sha256"],
            f"{suite}: wrong LCOV",
        )
        inputs[suite] = artifacts / f"{suite}.lcov"
        inputs[suite].write_bytes(data)
    cli = binaries / "hoonarqube"
    reports = scan_coverage_cases(receipt, root, work, cli, inputs, artifacts)
    check(
        set(reports)
        == {
            f"{case}-{mode}"
            for case in receipt["cases"]
            for mode in ("full", "one_decimal")
        },
        "incomplete Commander results",
    )
    revisions = {}
    for label, report in reports.items():
        name, mode = label.split("-", 1)
        scope(report, receipt["source"], receipt["source_sha256"])
        coverage_reference(name, mode, receipt["cases"][name], report)
        revisions[label] = receipt["source"]["commit"]

    dup = json.loads(DUPLICATION.read_bytes())
    check(
        set(dup["cases"]) == {"picomatch", "yjs"}, "expected two duplication captures"
    )
    for name, case in dup["cases"].items():
        row, files = case["source"], case["file_scope"]["sha256_by_path"]
        root = checkout(work, name, row, files, local)
        config = work / f"{name}-gate.json"
        config.write_text(json.dumps(dup["native"]["gate_configuration"]))
        args = [
            cli,
            "analyze",
            *row["sources"],
            "--profile",
            "sonar-parity",
            "--format",
            "json",
            "--quality-gate",
            config,
        ]
        for exclude in row["exclude"]:
            args += ["--exclude", exclude]
        run = subprocess.run(args, cwd=root, capture_output=True, timeout=180)
        report = json.loads(run.stdout)
        scope(report, row, files)
        gate = report["assessment"]["gate"]
        duplication_reference(case["reference"], gate)
        check(
            gate["conditions"] == case["native"]["assessment"]["gate"]["conditions"]
            and run.returncode == case["native"]["exit_code"],
            f"{name}: native condition/exit differs",
        )
        print(f"{name}: {gate['status']}", flush=True)
        reports[name] = report
        revisions[name] = row["commit"]
    verify_uploads(binaries / "hoonarqube-service", work, revisions, reports)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binaries", type=Path)
    parser.add_argument(
        "--local",
        type=Path,
        help="use clean pinned Git checkouts named commander, picomatch and yjs",
    )
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="hoonarqube-gate-") as scratch:
        replay(
            Path(scratch).resolve(),
            args.binaries.resolve(strict=True),
            args.local.resolve(strict=True) if args.local else None,
        )
