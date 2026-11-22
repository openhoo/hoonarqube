"""Compact and verify Commander Community Build decisions from six two-scan captures."""

import argparse
import hashlib
import json
from pathlib import Path

from public_coverage_gate_replay import check

REFERENCE = Path(__file__).with_name("community-commander-sonar-26.9.json")


def read(path):
    return json.loads(path.read_bytes())


def extract(folder):
    """Project the original CE, assigned period, gate status and measure responses."""
    cases = {}
    scm = read(folder / "scm-membership.json")
    for capture, policy in (("live-commander", False), ("live-commander-policy", True)):
        gate = read(folder / capture / "gate.json")
        for path in sorted((folder / capture).iterdir()):
            if not path.is_dir():
                continue
            base, suite = path.name.split("-")
            name = ("policy" if policy else suite) + "-" + base
            assigned = read(path / "assigned.json")["qualityGate"]
            check(
                assigned["name"] == gate["name"] and assigned["default"] is False,
                "expected a dedicated project gate",
            )
            stages = {}
            for stage in ("baseline", "candidate"):
                task = read(path / stage / "confirmed.json")
                invocation = read(path / stage / "scanner-execution.json")
                check(invocation["exit_code"] == 0, "scanner failed")
                (rev,) = (
                    a.split("=", 1)[1]
                    for a in invocation["argv"]
                    if a.startswith("-Dsonar.scm.revision=")
                )
                stages[stage] = {**task, "revision": rev}
            period = read(path / "candidate" / "period.json")
            metrics = read(path / "measures.json")["component"]
            check(
                period["projectKey"] == metrics["key"],
                "captures use different projects",
            )
            cases[name] = {
                "project": metrics["key"],
                "scm_only": {
                    p: r["scm_only"]
                    for p, r in scm[stages["baseline"]["revision"]].items()
                    if r["scm_only"]
                },
                "gate": assigned["name"],
                **stages,
                "lcov_sha256": hashlib.sha256(
                    (path / "candidate/measurements.lcov").read_bytes()
                ).hexdigest(),
                "period": {
                    k: period[k] for k in ("projectKey", "branchKey", "type", "value")
                },
                "decision": read(path / "decision.json")["projectStatus"],
                "measures": {
                    m["metric"]: m.get("period", m)["value"]
                    for m in metrics["measures"]
                },
            }
    check(len(cases) == 6, "incomplete Commander reference capture")
    return {"server_version": "26.9.0.129388", "cases": cases}


def verify(
    case, suite, base, revision, digest, overall, scoped, changed, result, rc, policy
):
    """Compare independent Git, LCOV and CLI results to both analyses of the assigned project."""
    project = f"hq-commander-combined-20261122-{base[:8]}-{suite}" + (
        "-95" if policy else ""
    )
    before, after = case["baseline"], case["candidate"]
    for task, expected in ((before, base), (after, revision)):
        check(
            task["status"] == "SUCCESS"
            and task["componentKey"] == case["project"] == project
            and task["revision"] == expected
            and task["analysisId"]
            and task["id"],
            "unexpected Community analysis",
        )
    check(
        before["analysisId"] != after["analysisId"] and before["id"] != after["id"],
        "candidate reused baseline analysis",
    )
    decision = case["decision"]
    check(
        case["lcov_sha256"] == digest
        and case["period"]
        == {
            "projectKey": project,
            "branchKey": "main",
            "type": "SPECIFIC_ANALYSIS",
            "value": before["analysisId"],
        }
        and decision["period"]["mode"] == "SPECIFIC_ANALYSIS"
        and decision["period"]["parameter"] == before["analysisId"],
        "wrong LCOV or reference baseline",
    )
    measures = case["measures"]
    for prefix, (lh, lt, bh, bt) in (("", overall), ("new_", scoped)):
        for key, expected in (
            ("lines_to_cover", lt),
            ("uncovered_lines", lt - lh),
            ("conditions_to_cover", bt),
            ("uncovered_conditions", bt - bh),
        ):
            check(
                int(measures[prefix + key]) == expected,
                f"Community count differs: {prefix}{key}",
            )
    # Community includes the trailing empty line of index.js in the older diff.
    # This is a physical-line difference; that line has no LCOV observation.
    scm_extra = case["scm_only"]
    check(
        scm_extra == ({"index.js": [22]} if base.startswith("b51c0ea3") else {}),
        "unexpected SCM-only lines",
    )
    check(
        int(measures["new_lines"]) == changed + sum(map(len, scm_extra.values())),
        "Community changed line count differs",
    )
    native = {
        "new_coverage" if c["scope"] == "new_code" else "coverage": c
        for c in result["conditions"]
    }
    conditions = decision["conditions"]
    expected_metrics = {"new_coverage"} if policy else {"coverage", "new_coverage"}
    check(
        {c["metricKey"] for c in conditions} == native.keys() == expected_metrics
        and len(conditions) == len(result["conditions"]) == len(expected_metrics),
        "unexpected gate conditions",
    )
    for ref in conditions:
        key = ref["metricKey"]
        cond = native[key]
        check(
            ref["comparator"] == "LT"
            and cond["operator"] == "gte"
            and float(ref["errorThreshold"])
            == cond["threshold"]
            == (95 if policy else 80)
            and cond["actual"] == float(ref["actualValue"]) == float(measures[key])
            and (ref["status"], cond["status"]) in (("OK", "pass"), ("ERROR", "fail")),
            f"Community condition differs: {key}",
        )
    ignored = any(c.get("ignored_on_small_change") is not None for c in native.values())
    check(decision["ignoredConditions"] is ignored, "wrong ignoredConditions flag")
    check(
        (decision["status"], result["status"], rc)
        in (("OK", "pass", 0), ("ERROR", "fail", 1)),
        "Community verdict differs",
    )
    return after["analysisId"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture_directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(extract(args.capture_directory), indent=2))
