"""Build and test Blinker, then verify native CI exits and assigned service gates."""

import argparse
import base64
import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

from inputs import (
    HERE,
    MANIFEST,
    digest,
    platform_for_host,
    require,
    source,
    test_wheel,
    wheels,
)

sys.path.insert(0, str(HERE.parents[2] / "scripts"))
from smoke_cli_service import request, running_service

REF = json.loads((HERE / "reference.json").read_bytes())
METRICS = ("coverage", "line_coverage")
CONFIG = {
    "schema_version": 1,
    "conditions": [
        {
            "scope": "overall",
            "metric": m,
            "operator": "gte",
            "threshold": 80,
            "precision": "one_decimal",
        }
        for m in METRICS
    ],
}


def check_reference(case):
    ref = REF[case]
    gate = ref["gate"]["projectStatus"]
    cs = gate["conditions"]
    require(
        ref["revision"] == MANIFEST["commit"]
        and ref["task"]["status"] == "SUCCESS"
        and ref["task"]["analysisId"]
        and ref["version"] == "26.9.0.129388"
        and ref["profile"] == "Sonar way",
        "unqualified reference",
    )
    require(
        not ref["policy"]["qualityGate"]["default"] and not gate["ignoredConditions"],
        "reference gate not assigned or condition ignored",
    )
    require(
        gate["status"] == ("OK" if case == "full" else "ERROR")
        and sorted(
            (c["metricKey"], c["comparator"], float(c["errorThreshold"]), c["status"])
            for c in cs
        )
        == [(m, "LT", 80, gate["status"]) for m in METRICS],
        "reference policy changed",
    )
    require(
        len({r["task"]["analysisId"] for r in REF.values()}) == 3,
        "reference reused an analysis",
    )
    return {c["metricKey"]: float(c["actualValue"]) for c in cs}


def verify_coverage(report, case):
    coverage = report["assessment"].get("coverage")
    if case == "missing":
        require(coverage is None, "an absent coverage report produced measurements")
        return
    require(
        coverage["status"] == "complete"
        and not coverage["diagnostics"]
        and len(coverage["inputs"]) == 1
        and coverage["inputs"][0]["content_digest"] == REF[case]["lcov_sha256"],
        "coverage skipped or input changed",
    )
    files = {f["path"]: f["lines"] for f in coverage["files"]}
    ref_files = REF[case]["files"]["components"]
    require(set(files) == {r["path"] for r in ref_files}, "wrong coverage file set")
    for ref in ref_files:
        lines = files[ref["path"]]
        m = {
            v["metric"]: int(v["value"])
            for v in ref["measures"]
            if v["metric"] not in METRICS
        }
        branches = [line["branches"] for line in lines if "branches" in line]
        actual = (
            len(lines),
            sum(not line["covered"] for line in lines),
            sum(b["eligible"] for b in branches),
            sum(b["eligible"] - b["covered"] for b in branches),
        )
        expected = tuple(
            m.get(key, 0)
            for key in (
                "lines_to_cover",
                "uncovered_lines",
                "conditions_to_cover",
                "uncovered_conditions",
            )
        )
        require(
            actual == expected, f"{case}: reference coverage differs in {ref['path']}"
        )


def scan(cli, src, git_dir, case, lcov):
    expected_values = check_reference(case)
    path = src / "measured.lcov"
    path.unlink(missing_ok=True)
    args = [
        str(cli),
        "analyze",
        "src/blinker",
        "--assessment",
        "--profile",
        "sonar-parity",
        "--format",
        "json",
    ]
    if lcov is not None:
        require(digest(lcov) == REF[case]["lcov_sha256"], f"{case}: raw LCOV differs")
        path.write_bytes(lcov)
        args += ["--coverage-lcov", path.name]
    env = {
        **os.environ,
        "GIT_DIR": str(git_dir),
        "GIT_WORK_TREE": str(src),
        "GIT_OPTIONAL_LOCKS": "0",
    }

    def invoke(extra, exit_code):
        result = subprocess.run(
            [*args, *extra], cwd=src, env=env, capture_output=True, timeout=90
        )
        require(
            result.returncode == exit_code,
            f"{case}: wanted exit {exit_code}, got {result.returncode}: {result.stderr.decode()[-500:]}",
        )
        return json.loads(result.stdout)

    report = invoke([], 0)
    project = report["project"]
    scope = {item["path"] for item in REF[case]["files"]["components"]}
    require(
        project["complete"]
        and all(
            f["classification"] == "source" and f["status"] == "complete"
            for f in project["files"]
        )
        and all(
            len(rows) == len(scope) and {f["path"] for f in rows} == scope
            for rows in (project["files"], report["files"])
        ),
        "scan was incomplete or differently scoped",
    )
    require(
        report["assessment"]["context"]["source_revision"] == MANIFEST["commit"]
        and report["parity"]["reference"]["profile"] == "sonar-parity"
        and not report["parity"]["rule_set_violations"]
        and "gate" not in report["assessment"],
        "wrong source, profile or scanner gate",
    )
    verify_coverage(report, case)
    code, state = {
        "full": (0, "pass"),
        "focused": (1, "fail"),
        "missing": (2, "unavailable"),
    }[case]
    gate = invoke(["--quality-gate", "gate-policy.json"], code)["assessment"]["gate"]
    require(
        [
            {key: cond.get(key) for key in CONFIG["conditions"][0]}
            for cond in gate["conditions"]
        ]
        == CONFIG["conditions"],
        "CLI returned different scope, operator, threshold or precision",
    )
    actual = {c["metric"]: c.get("actual") for c in gate["conditions"]}
    expected = expected_values if case != "missing" else {m: None for m in METRICS}
    require(
        actual == expected
        and gate["status"] == state
        and len(gate["conditions"]) == len(expected)
        and all(c["status"] == state for c in gate["conditions"]),
        f"{case}: {gate}",
    )
    return report, gate, code


def replay(binaries, work, mirror, cache, architecture):
    src, git_dir, epoch = source(work, mirror)
    built = test_wheel(src, wheels(work, architecture, cache), epoch, architecture)
    (src / "gate-policy.json").write_text(json.dumps(CONFIG))
    db = work / "db"
    db.mkdir()
    token = secrets.token_urlsafe(32)
    srv = binaries / "hoonarqube-service"
    rows = {}
    summary = {}
    with running_service(srv, db, token) as port:
        assignment = request(
            port,
            token,
            "/smoke/gate-policy",
            {"schema_version": 1, "expected_version": 0, "config": CONFIG},
            method="PUT",
        )["policy"]
        require(
            assignment["version"] == 1 and assignment["config"] == CONFIG,
            "policy assignment failed",
        )
        for case in ("full", "focused", "missing"):
            lcov = (
                base64.b64decode(built[case]["lcov"], validate=True)
                if case in built
                else None
            )
            report, gate, code = scan(binaries / "hoonarqube", src, git_dir, case, lcov)
            body = {
                "schema_version": 1,
                "branch": case,
                "commit": MANIFEST["commit"],
                "analyzed_at": "2026-11-22T00:00:00Z",
                "report": report,
            }
            result = request(port, token, "/smoke/analyses", body)
            row = result["analysis"]
            rid = row["id"]
            stored = request(port, token, f"/smoke/analyses/{rid}/gate")
            require(
                not result["idempotent"]
                and row["gate_policy_version"] == 1
                and row["gate"] == stored == gate,
                "server-assigned gate differs from CLI",
            )
            rows[case] = (rid, body, gate)
            summary[case] = {
                "tests": built.get(case, {}).get("passed"),
                "exit": code,
                "gate": gate["status"],
                "values": {c["metric"]: c.get("actual") for c in gate["conditions"]},
            }
    with running_service(srv, db, token) as port:
        for rid, body, gate in rows.values():
            require(
                request(port, token, f"/smoke/analyses/{rid}/gate") == gate,
                "restart changed gate",
            )
            again = request(port, token, "/smoke/analyses", body)
            require(
                again["idempotent"] and again["analysis"]["id"] == rid,
                "retry changed analysis",
            )
    return summary


def main():
    arg = argparse.ArgumentParser(description=__doc__)
    arg.add_argument("binaries", type=Path)
    arg.add_argument(
        "--repository", default="https://github.com/pallets-eco/blinker.git"
    )
    arg.add_argument(
        "--wheel-cache",
        type=Path,
        help="Offline directory with the seven verified architecture-specific wheels.",
    )
    arg.add_argument(
        "--architecture",
        choices=("amd64", "arm64"),
        default=platform_for_host(),
        help="Architecture of the offline Linux build container.",
    )
    opts = arg.parse_args()
    with tempfile.TemporaryDirectory() as work:
        print(
            json.dumps(
                replay(
                    opts.binaries.resolve(),
                    Path(work).resolve(),
                    opts.repository,
                    opts.wheel_cache,
                    opts.architecture,
                ),
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
