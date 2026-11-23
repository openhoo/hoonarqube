"""Build and test Blinker, then verify native CI exits and assigned service gates."""

import argparse
import base64
import json
import os
import re
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
COVERAGE_SUFFIXES = {"lcov": "lcov", "cobertura": "xml"}
XML_TIMESTAMP = re.compile(
    rb'(\A<\?xml [^>\r\n]*>\n<coverage\b[^>\r\n]*? timestamp=")[0-9]+(")'
)
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


def verify_coverage(report, case, provenance):
    coverage = report["assessment"].get("coverage")
    if provenance is None:
        require(coverage is None, "an absent coverage report produced measurements")
        return
    require(
        coverage["status"] == "complete"
        and not coverage["diagnostics"]
        and coverage["inputs"] == [provenance],
        f"{case}: coverage skipped or input changed: {provenance}",
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
    return coverage


def verify_artifact(case, kind, artifact):
    raw_sha256 = digest(artifact)
    if kind == "lcov":
        require(raw_sha256 == REF[case]["lcov_sha256"], f"{case}: raw LCOV differs")
        return raw_sha256, None
    normalized, replacements = XML_TIMESTAMP.subn(rb"\g<1>0\2", artifact)
    normalized_sha256 = digest(normalized)
    require(
        replacements == 1
        and normalized_sha256 == REF[case]["cobertura_timestamp_normalized_sha256"],
        f"{case}: Cobertura XML differs after normalizing the root timestamp",
    )
    return raw_sha256, normalized_sha256


def scan(cli, src, git_dir, case, kind, artifact):
    expected_values = check_reference(case)
    for suffix in COVERAGE_SUFFIXES.values():
        (src / f"measured.{suffix}").unlink(missing_ok=True)
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
    provenance = None
    normalized_sha256 = None
    if kind is not None:
        path = src / f"measured.{COVERAGE_SUFFIXES[kind]}"
        raw_sha256, normalized_sha256 = verify_artifact(case, kind, artifact)
        provenance = {
            "path": path.name,
            "format": kind,
            "content_digest": raw_sha256,
        }
        path.write_bytes(artifact)
        args += [f"--coverage-{kind}", path.name]
    env = {
        **os.environ,
        "GIT_DIR": str(git_dir),
        "GIT_WORK_TREE": str(src),
        "GIT_OPTIONAL_LOCKS": "0",
    }

    def invoke(extra, exit_code):
        result = subprocess.run(
            [*args, *extra],
            check=False,
            cwd=src,
            env=env,
            capture_output=True,
            timeout=90,
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
    coverage = verify_coverage(report, case, provenance)
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
    evidence = {"exit": code, "gate": state, "values": actual}
    if coverage is not None:
        evidence.update(
            input=provenance,
            lines=coverage["lines"],
            branches=coverage["branches"],
            files_verified=sorted(file["path"] for file in coverage["files"]),
        )
    if normalized_sha256 is not None:
        evidence["timestamp_normalized_sha256"] = normalized_sha256
    return report, gate, evidence


def replay(binaries, work, mirror, cache, architecture):
    src, git_dir, epoch = source(work, mirror)
    built = test_wheel(src, wheels(work, architecture, cache), epoch, architecture)
    (src / "gate-policy.json").write_text(json.dumps(CONFIG))
    db = work / "db"
    db.mkdir()
    token = secrets.token_urlsafe(32)
    srv = binaries / "hoonarqube-service"
    rows = []
    summary = {
        "revision": MANIFEST["commit"],
        "linux_architecture": built["architecture"],
        "wheel_sha256": built["wheel_sha256"],
        "cases": {},
    }
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
            reports = {}
            summary["cases"][case] = {
                "tests": built.get(case, {}).get("passed"),
                "reports": reports,
            }
            measurements = None
            for kind in COVERAGE_SUFFIXES if case != "missing" else (None,):
                artifact = (
                    base64.b64decode(built[case][kind], validate=True)
                    if kind is not None
                    else None
                )
                report, gate, evidence = scan(
                    binaries / "hoonarqube", src, git_dir, case, kind, artifact
                )
                if kind is not None:
                    files = report["assessment"]["coverage"]["files"]
                    require(
                        measurements is None or files == measurements,
                        f"{case}: per-line coverage differs between XML and LCOV",
                    )
                    measurements = files
                body = {
                    "schema_version": 1,
                    "branch": f"{case}-{kind}" if kind else case,
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
                    f"{case}/{kind}: server-assigned gate differs from CLI",
                )
                rows.append((rid, body, gate))
                reports[kind or "none"] = evidence
    with running_service(srv, db, token) as port:
        for rid, body, gate in rows:
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
