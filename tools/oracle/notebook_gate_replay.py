"""Use the native CI gate on the exact inputs of an assigned Community notebook rule profile."""

import json
import subprocess
from pathlib import Path

from public_coverage_gate_replay import check


CAPTURE = Path(__file__).with_name("fixtures") / "notebook-task-gates-2611.json"
RULE = "ipython:S7502"


def run_gate(root, binary, paths, threshold=0):
    proc = subprocess.run(
        [
            binary,
            "notebook-gate",
            "--json",
            "--max-violations",
            str(threshold),
            "--",
            *paths,
        ],
        cwd=root,
        capture_output=True,
        check=False,
        timeout=45,
    )
    return proc.returncode, json.loads(proc.stdout)


def scopes():
    data = json.loads(CAPTURE.read_bytes())
    profile, gate = data["profile"], data["gate"]
    check(
        data["community"] == "26.11.0.134175"
        and profile["rules"] == [RULE]
        and not profile["default"]
        and not gate["default"]
        and gate["metric"] == "violations"
        and gate["op"] == "GT"
        and gate["error"] == 0,
        "different assigned reference policy",
    )
    labels = {x["label"] for x in data["cases"]}
    check(
        len(data["cases"]) == 6
        and labels
        == {
            "nbdime-all",
            "ipywidgets-source",
            "ipywidgets-control",
            "ipywidgets-all",
            "nbclassic-all",
            "nbclassic-source",
        },
        "missing or duplicate assigned notebook references",
    )
    return data["cases"]


def compare(root, binary, original, row, unavailable):
    paths = row["files"]
    rc, own = run_gate(root, binary, reversed(paths))
    check(
        row["revision"] == original["commit"]
        and row["repository"] == original["repository"]
        and set(paths) <= original["files"].keys()
        and len(paths) == len(set(paths))
        and row["decision"] == ("ERROR" if row["actual"] else "OK")
        and row["actual"] == len(row["issues"]),
        "scope, revision or reference count drift",
    )
    bad = set(paths) & unavailable.keys()
    counts = {
        path: sum(issue["path"] == path for issue in row["issues"]) for path in paths
    }
    check(
        own["profile_rules"] == [RULE]
        and own["metric"] == "violations"
        and own["operator"] == "lte"
        and own["threshold"] == 0
        and own["schema_version"] == 1
        and [item["path"] for item in own["inputs"]] == sorted(paths),
        "unbound local gate",
    )
    for item in own["inputs"]:
        path = item["path"]
        check(
            item["sha256"] == original["files"][path]["sha256"]
            and item["violations"] == (None if path in bad else counts[path])
            and (bool(item["diagnostic"]) == (path in bad)),
            f"{path}: wrong gate input",
        )
    expected = (
        (2, "unavailable", None)
        if bad
        else ((1, "fail", row["actual"]) if row["actual"] else (0, "pass", 0))
    )
    check(
        (rc, own["status"], own["actual"]) == expected,
        f"{row['label']}: incorrect CI decision",
    )
    return own["status"]
