"""Verify four Community analyses and both native gate precisions on Jupyter packages."""

import argparse
import json
import math
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile

from public_contract import git, require, safe_path, stage
from python_duplication import positive_files

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
from smoke_cli_service import request, running_service  # noqa: E402

METRIC = "duplicated_lines_density"
FIXTURE = HERE / "fixtures/jupyter-package-density-2611.json"


def scan(cli, root, case, options, expected):
    proc = subprocess.run(
        [
            cli,
            "analyze",
            *sorted(case["files"]),
            "--format",
            "json",
            "--profile",
            "sonar-parity",
            *options,
        ],
        cwd=root,
        capture_output=True,
        timeout=120,
    )
    require(
        proc.returncode == expected,
        f"{case['repository']}: expected CLI {expected}, "
        f"got {proc.returncode}: {proc.stderr.decode(errors='replace')[:400]}",
    )
    return json.loads(proc.stdout)


def check_source_measurements(case, raw):
    measures = case["reference_measures"]
    files = raw["project"]["files"]
    require(
        raw["project"]["complete"]
        and len(files) == len(case["files"])
        and {f["path"] for f in files} == set(case["files"])
        and all(
            f["status"] == "complete" and f["classification"] == "source" for f in files
        ),
        "incomplete package inventory",
    )
    marked = {
        path: [line for lo, hi in data["ranges"] for line in range(lo, hi + 1)]
        for path, data in positive_files(raw).items()
    }
    require(
        marked == case["duplicated_lines"], "reference duplicated line locations differ"
    )
    lines = sum(f["metrics"]["lines"] for f in files)
    duplicates = sum(map(len, marked.values()))
    require(
        (lines, duplicates)
        == (int(measures["lines"]), int(measures["duplicated_lines"])),
        "reference project counters differ",
    )
    return duplicates / lines * 100


def check_assigned(service, scratch, case, raw, config, gate, expected):
    token = secrets.token_urlsafe(32)
    with tempfile.TemporaryDirectory(dir=scratch) as db:
        with running_service(service, Path(db), token) as port:
            request(
                port,
                token,
                "/smoke/gate-policy",
                {"schema_version": 1, "expected_version": 0, "config": config},
                method="PUT",
            )
            receipt = request(
                port,
                token,
                "/smoke/analyses",
                {
                    "schema_version": 1,
                    "branch": "main",
                    "commit": case["commit"],
                    "analyzed_at": "2026-11-23T00:00:00Z",
                    "report": raw,
                },
            )
            row = receipt["analysis"]
            require(
                row["gate"] == gate and row["gate_policy_version"] == 1,
                "assigned policy did not reproduce the CLI decision",
            )
            ci = subprocess.run(
                [
                    sys.executable,
                    SCRIPTS / "check_project_gate.py",
                    "--project",
                    "smoke",
                    "--branch",
                    "main",
                    "--commit",
                    case["commit"],
                ],
                input=json.dumps(receipt).encode(),
                capture_output=True,
                timeout=30,
            )
            require(
                ci.returncode == expected and b"Project gate version 1:" in ci.stdout,
                "CI receipt did not reproduce the assigned decision",
            )
        with running_service(service, Path(db), token) as port:
            require(
                request(port, token, f"/smoke/analyses/{row['id']}/gate") == gate,
                "stored decision changed after restart",
            )
        return ci.returncode


def compare(binaries, case, local):
    with tempfile.TemporaryDirectory() as tmp:
        scratch = Path(tmp)
        name = case["repository"].split("/")[-1]
        require(
            case["repository"] == "jupyter/" + safe_path(name),
            "unexpected source repository",
        )
        for path in case["files"]:
            safe_path(path)
        root = stage(case, scratch, local)
        entries = (
            git(
                local or scratch / "objects",
                "ls-tree",
                "-rz",
                "--name-only",
                case["commit"],
                "--",
                name,
            )
            .decode()
            .split("\0")
        )
        require(
            {p for p in entries if p.endswith(".py")} == set(case["files"]),
            "captured files differ from the full Python package",
        )
        cli = binaries / "hoonarqube"
        raw = scan(cli, root, case, ["--assessment"], 0)
        full = check_source_measurements(case, raw)
        results = []
        thresholds = [
            float(a["gate"]["conditions"][0]["errorThreshold"])
            for a in case["analyses"]
        ]
        require(
            thresholds == ([3.0, 3.39] if name == "nbformat" else [3.0]),
            "missing reference threshold",
        )
        for capture in case["analyses"]:
            reference = capture["gate"]
            (condition,) = reference["conditions"]
            threshold = float(condition["errorThreshold"])
            rounded = float(condition["actualValue"])
            require(
                not reference["ignoredConditions"]
                and condition["metricKey"] == METRIC
                and condition["comparator"] == "GT"
                and reference["status"]
                == condition["status"]
                == ("ERROR" if rounded > threshold else "OK")
                and rounded == float(case["reference_measures"][METRIC]),
                "unexpected independent reference gate",
            )
            for precision, value in [("full", full), ("one_decimal", rounded)]:
                cond = dict(
                    metric=METRIC, scope="overall", operator="lte", threshold=threshold
                )
                if precision == "one_decimal":
                    cond["precision"] = precision
                config = dict(schema_version=1, conditions=[cond])
                policy = scratch / "policy.json"
                policy.write_text(json.dumps(config))
                expected = int(value > threshold)
                report = scan(cli, root, case, ["--quality-gate", policy], expected)
                gate = report["assessment"]["gate"]
                (actual,) = gate["conditions"]
                require(
                    gate["status"]
                    == actual["status"]
                    == ("fail" if expected else "pass")
                    and math.isclose(actual["actual"], value, rel_tol=1e-14)
                    and actual["threshold"] == threshold,
                    "gate value or decision changed",
                )
                ci = check_assigned(
                    binaries / "hoonarqube-service",
                    scratch,
                    case,
                    raw,
                    config,
                    gate,
                    expected,
                )
                results.append(
                    dict(
                        analysis=capture["analysis"],
                        threshold=threshold,
                        precision=precision,
                        actual=actual["actual"],
                        cli_exit=expected,
                        ci_exit=ci,
                        restart=True,
                        reference_gate=reference["status"],
                    )
                )
        return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "binaries", type=Path, help="Directory with candidate CLI and service"
    )
    parser.add_argument(
        "--sources",
        type=Path,
        help="Optional local Git checkouts named after the packages",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    data = json.loads(FIXTURE.read_bytes())
    cases = data["packages"]
    require(
        data["community_version"] == "26.11.0.134175"
        and {k: len(v["files"]) for k, v in cases.items()}
        == {"nbclient": 8, "nbformat": 40, "nbconvert": 72}
        and len({a["analysis"] for c in cases.values() for a in c["analyses"]}) == 4,
        "incomplete reference corpus",
    )
    results = {}
    for name, case in cases.items():
        results[name] = compare(
            args.binaries.resolve(strict=True),
            case,
            args.sources / name if args.sources else None,
        )
        for row in results[name]:
            print(
                f"{name} {row['threshold']}% {row['precision']}: {row['actual']}%, "
                f"CLI/CI {row['ci_exit']}; Community {row['reference_gate']}",
                flush=True,
            )
    if args.output:
        args.output.write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
