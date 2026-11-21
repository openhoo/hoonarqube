#!/usr/bin/env python3
"""Re-run selected Commander.js tests and compare native gates with the captured Sonar decisions."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile

RECEIPT = Path(__file__).with_name("public-line-coverage-gates-20261120.json")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(ok, reason):
    if not ok:
        raise ValueError(reason)


def run_tests(root, out, evidence, suite):
    test_set = evidence["test_sets"][suite]
    cmd = [
        "docker",
        "run",
        "--rm",
        "--pull=never",
        "--platform=linux/arm64",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        "65534:65534",
        "--pids-limit",
        "80",
        "--memory",
        "512m",
        "--cpus",
        "2",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=64m",
        "-v",
        f"{root}:/src:ro",
        "-w",
        "/src",
        "--entrypoint",
        "node",
        evidence["node_image"],
        "--test",
        "--experimental-test-coverage",
        "--test-coverage-include=index.js",
        "--test-coverage-include=lib/*.js",
        "--test-reporter=lcov",
        "--test-reporter-destination=stdout",
        "--test-reporter=spec",
        "--test-reporter-destination=stderr",
        *test_set["test_files"],
    ]
    p = subprocess.run(cmd, capture_output=True, timeout=180, check=False)
    (out / f"{suite}-tests.log").write_bytes(p.stderr)
    coverage = out / f"{suite}.lcov"
    coverage.write_bytes(p.stdout)
    check(p.returncode == 0, f"{suite}: Node tests failed")
    for key, value in (
        ("tests", test_set["passed"]),
        ("pass", test_set["passed"]),
        ("fail", 0),
        ("skipped", 0),
        ("cancelled", 0),
    ):
        check(
            re.search(rf"^ℹ {key} {value}$", p.stderr.decode(), re.M),
            f"{suite}: unexpected {key}",
        )
    # The Node reporter can emit functions in a different order. Compare the
    # actual coverage of every source line and the decisions, not LCOV ordering.
    return coverage


def line_counts(path, source_paths):
    records = {}
    for record in path.read_text().split("end_of_record"):
        if not record.strip():
            continue
        paths = [s[3:] for s in record.splitlines() if s.startswith("SF:")]
        check(
            len(paths) == 1 and paths[0] not in records,
            "invalid or duplicate LCOV file",
        )
        lines = {}
        for row in record.splitlines():
            if row.startswith("DA:"):
                fields = row[3:].split(",")
                number, count = map(int, fields[:2])
                check(
                    number > 0 and count >= 0 and number not in lines,
                    "invalid or duplicate LCOV line",
                )
                lines[number] = count > 0
        records[paths[0]] = lines
    check(set(records) == set(source_paths), "LCOV file scope changed")
    return {
        name: {
            "eligible": len(hits),
            "covered": sum(hits.values()),
            "line_hit_map_sha256": hashlib.sha256(
                "".join(f"{line}:{int(hits[line])}\n" for line in sorted(hits)).encode()
            ).hexdigest(),
        }
        for name, hits in records.items()
    }


def verify_uploads(service, destination, revisions, cases):
    # Reuse the release smoke test's loopback-only service and scoped credential.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
    from smoke_cli_service import request, running_service

    token = secrets.token_urlsafe(32)
    route = "/smoke/analyses"
    with tempfile.TemporaryDirectory(dir=destination) as temp:
        stored = {}
        with running_service(service, Path(temp), token) as port:
            for name, report in cases.items():
                body = {
                    "branch": name,
                    "commit": revisions[name],
                    "analyzed_at": "2026-11-20T00:00:00Z",
                    "schema_version": 1,
                    "report": report,
                }
                first = request(port, token, route, body)
                check(first["idempotent"] is False, f"{name}: expected first upload")
                stored[name] = body, first["analysis"]["id"]
            for key in ("actual", "precision"):
                body = copy.deepcopy(stored["decimal-one_decimal"][0])
                body["branch"] = f"invalid-{key}"
                condition = body["report"]["assessment"]["gate"]["conditions"][0]
                if key == "actual":
                    condition[key] = 60.0
                else:
                    del condition[key]
                try:
                    request(port, token, route, body)
                except RuntimeError as exc:
                    check("HTTP 409:" in str(exc), f"{key}: expected conflict")
                else:
                    raise ValueError(f"{key}: inconsistent gate claim was accepted")
        with running_service(service, Path(temp), token) as port:
            for name, (body, analysis_id) in stored.items():
                detail = request(port, token, f"{route}/{analysis_id}")["analysis"]
                check(detail["report"] == body["report"], f"{name}: report changed")
                retry = request(port, token, route, body)
                check(
                    retry["idempotent"] and retry["analysis"]["id"] == analysis_id,
                    f"{name}: retry did not return the same analysis",
                )
        print(f"{len(stored)} reports persisted and retried; 2 conflicts rejected")


def replay(root, destination, binary, service=None):
    evidence = json.loads(RECEIPT.read_text())

    def git(*args):
        return subprocess.check_output(["git", "-C", root, *args], text=True).strip()

    check(
        git("rev-parse", "HEAD") == evidence["source"]["commit"],
        "unexpected public revision",
    )
    check(
        git("rev-parse", "HEAD^{tree}") == evidence["source"]["tree"],
        "unexpected public tree",
    )
    clean = ("status", "--porcelain", "--untracked-files=all", "--ignored=matching")
    check(not git(*clean), "source checkout must be clean, including ignored files")
    check(
        not destination.is_relative_to(root),
        "output must be outside the public checkout",
    )
    sources = evidence["source_sha256"]
    check(
        all(sha256(root / name) == digest for name, digest in sources.items()),
        "source bytes changed",
    )
    destination.mkdir(parents=True, exist_ok=False)
    coverage = {
        suite: run_tests(root, destination, evidence, suite)
        for suite in evidence["test_sets"]
    }
    # Coverage input names survive in the report. Produce portable names at
    # scan time while keeping the pinned upstream checkout pristine.
    stage = destination / "scan-source"
    subprocess.run(
        ["git", "clone", "--quiet", "--local", "--no-checkout", "--", root, stage],
        check=True,
    )
    revision = evidence["source"]["commit"]
    subprocess.run(
        ["git", "-C", stage, "checkout", "-q", "--detach", revision], check=True
    )
    artifacts = stage / ".hoonarqube-replay"
    artifacts.mkdir()
    for path in coverage.values():
        shutil.copyfile(path, artifacts / path.name)
    checked = scan_coverage_cases(
        evidence, stage, destination, binary, coverage, artifacts
    )
    check(not git(*clean), "public source changed during replay")
    if service is not None:
        verify_uploads(service, destination, dict.fromkeys(checked, revision), checked)


def scan_coverage_cases(evidence, stage, destination, binary, coverage, artifacts):
    """Check both native precision modes against the recorded report contract."""
    checked = {}
    for name, case in evidence["cases"].items():
        suite = case["tests"]
        threshold = float(case["reference"]["condition"]["errorThreshold"])
        if suite:
            check(
                line_counts(coverage[suite], evidence["source_sha256"])
                == case["line_counts_by_file"],
                f"{name}: line counts changed",
            )
        for mode in ("full", "one_decimal"):
            condition = dict(
                scope="overall",
                metric="line_coverage",
                operator="gte",
                threshold=threshold,
            )
            if mode != "full":
                condition["precision"] = mode
            config = destination / f"{name}-{mode}-gate.json"
            config.write_text(
                json.dumps({"schema_version": 1, "conditions": [condition]}) + "\n"
            )
            cmd = [
                binary,
                "analyze",
                *evidence["source"]["sources"],
                "--format",
                "json",
                "--profile",
                "sonar-parity",
                "--quality-gate",
                config,
            ]
            if suite:
                cmd += [
                    "--coverage-lcov",
                    (artifacts / coverage[suite].name).relative_to(stage),
                ]
            p = subprocess.run(
                cmd, cwd=stage, capture_output=True, timeout=180, check=False
            )
            (destination / f"{name}-{mode}.json").write_bytes(p.stdout)
            report = json.loads(p.stdout)
            gate = report["assessment"]["gate"]
            want = (
                case["native_full_precision"]
                if mode == "full"
                else case["native_one_decimal"]
            )
            check(report["project"]["complete"], f"{name}: project incomplete")
            check(
                {x["path"] for x in report["project"]["files"]}
                == set(evidence["source_sha256"]),
                f"{name}: scope changed",
            )
            check(
                p.returncode == want["exit_code"] and gate["status"] == want["gate"],
                f"{name}: decision changed",
            )
            check(
                gate["conditions"] == [want["condition"]],
                f"{name}: evaluated condition changed",
            )
            print(name, mode, gate["status"], gate["conditions"][0]["actual"])
            checked[f"{name}-{mode}"] = report
    return checked


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("binary", type=Path)
    parser.add_argument(
        "--service", type=Path, help="also verify HTTP ingest, restart and retry"
    )
    args = parser.parse_args()
    replay(
        args.checkout.resolve(strict=True),
        args.output.resolve(),
        args.binary.resolve(strict=True),
        args.service.resolve(strict=True) if args.service else None,
    )
