"""Compare each measured Community 26.11 default condition on the pinned FastAPI change."""

import gzip
import json
import math
from collections import Counter
from pathlib import Path

from community_combined_coverage import gate
from community_new_duplication import CONFIG, check
from community_scm_period import descriptor, run_case
from public_corpus_summary import canonical_sha

FIXTURE = Path(__file__).with_name("fixtures") / "fastapi-default-gate-26.11.json.gz"


def validate_capture(ref, package):
    identities = set()
    for stage in ("base", "candidate"):
        pin = ref["source"][stage]
        hashes = {p: v[stage + "_sha256"] for p, v in package["files"].items()}
        check(
            pin["revision"] == package["pins"][stage]["revision"]
            and pin["tree"] == package["pins"][stage]["root_tree"]
            and pin["files_sha256"] == canonical_sha(hashes)
            and pin["file_count"] == len(hashes) == 48,
            "different package",
        )
        identities.update((pin["analysis"], pin["task"]))
    check(
        len(identities) == 4 and not (identities & set(package["analyses"].values())),
        "reused reference",
    )
    p, g = ref["profile"], ref["gate"]
    policy = {row["metric"]: (row["op"], row["error"]) for row in g["conditions"]}
    expected = {
        "new_coverage": ("LT", "80"),
        "new_violations": ("GT", "0"),
        "new_duplicated_lines_density": ("GT", "3"),
        "new_security_hotspots_reviewed": ("LT", "100"),
    }
    check(
        ref["version"] == "26.11.0.134175"
        and ref["repository"] == "fastapi/fastapi"
        and g["name"] == "Sonar way"
        and g["isBuiltIn"]
        and g["isDefault"]
        and ref["assignment"] == {"name": g["name"], "default": True}
        and len(g["conditions"]) == 4
        and policy == expected
        and p["name"] == "Sonar way core"
        and p["isDefault"]
        and p["isBuiltIn"]
        and p["language"] == "py"
        and p["activeRuleCount"] == len(ref["active_rules"]) == 232
        and not ref["coverage_report_supplied"]
        and ref["small_changes"]
        == [
            {
                "key": "sonar.qualitygate.ignoreSmallChanges",
                "value": "true",
                "inherited": True,
            }
        ],
        "different default configuration",
    )
    observed = ref["candidate"]
    values = {
        r["metricKey"]: (r["status"], float(r["actualValue"]))
        for r in observed["conditions"]
    }
    check(
        ref["baseline"]["conditions"] == []
        and not observed["ignoredConditions"]
        and observed["status"] == "ERROR"
        and len(observed["conditions"]) == 3
        and values
        == {
            "new_coverage": ("ERROR", 0.0),
            "new_violations": ("OK", 0.0),
            "new_duplicated_lines_density": ("ERROR", 4.87805),
        }
        and all(
            (r["comparator"], r["errorThreshold"]) == policy[r["metricKey"]]
            for r in observed["conditions"]
        )
        and ref["new_issue_count"] == ref["new_hotspot_count"] == 0,
        "different reference decision",
    )
    return descriptor(
        observed["period"],
        ref["source"]["base"]["analysis"],
        ref["source"]["base"]["revision"],
    )


def check_findings(report, active):
    by_path = {f["path"]: f["issues"] for f in report["files"]}
    new = Counter(
        by_path[e["path"]][e["issue_index"]]["rule_key"]
        for e in report["assessment"]["new_code"]["findings"]
        if e["status"] == "new"
    )
    check(
        not (new.keys() & active.keys()),
        "new finding for an active Python core rule; review against the reference",
    )
    return new


def replay_default(binary, root, work, package):
    ref = json.loads(gzip.decompress(FIXTURE.read_bytes()))
    selection = validate_capture(ref, package)
    coverage = {**gate("new_code"), "small_change_policy": "community20"}
    policy = [
        {
            "scope": "new_code",
            "metric": "violations",
            "operator": "lte",
            "threshold": 0,
        },
        coverage,
        CONFIG,
        {
            "scope": "new_code",
            "metric": "community_26_11_core_security_hotspots_reviewed",
            "operator": "gte",
            "threshold": 100,
        },
    ]
    code, report, _ = run_case(
        binary,
        root,
        work,
        sorted(package["files"]),
        selection["revision"],
        ref["source"]["candidate"]["revision"],
        selection,
        policy,
    )
    gate_report = report["assessment"]["gate"]
    c = {r["metric"]: r for r in gate_report["conditions"]}
    inactive = check_findings(report, ref["active_rules"])
    check(
        len(gate_report["conditions"]) == 4
        and set(c) == {r["metric"] for r in policy}
        and code == 2
        and gate_report["status"] == "unavailable"
        and c["coverage"]["status"] == "unavailable"
        and c["coverage"]["actual"] is None
        and c["duplicated_lines_density"]["status"] == "fail"
        and math.isclose(
            c["duplicated_lines_density"]["actual"],
            float(ref["measures"]["new_duplicated_lines_density"]),
            abs_tol=0.000005,
        )
        and c["community_26_11_core_security_hotspots_reviewed"]["status"] == "no_value"
        and c["violations"]["actual"] == sum(inactive.values()),
        "native condition or input availability changed",
    )
    return {
        "reference": ref["candidate"]["status"],
        "native": gate_report["status"],
        "native_inactive_new_findings": dict(sorted(inactive.items())),
        "reference_analysis": ref["source"]["candidate"]["analysis"],
    }
