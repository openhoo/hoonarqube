"""Read and verify the raw Community 26.9 responses for five public changes."""

import hashlib
import json
from math import isclose
from pathlib import Path

METRIC = "new_duplicated_lines_density"
SERVER = "26.9.0.129388"
SCANNER = "sonarsource/sonar-scanner-cli:12.1.0.3233_8.0.1@sha256:23ca0f137965d9dff2198074043fd48d386280bc5d0ccac8c8349cea4cf096a9"
# Each ID binds the scoped path (digest prefix) and two public Git revisions.
IDS = {
    "yjs": ("040e4a-53fd0285-486d5677", "8e03df-ebae7a3e-ee37f0a0"),
    "fastapi": (
        "4d5730-e0f8cadf-b78c8226",
        "e764e3-7cb19539-5d5666be",
        "d9b3d8-2bb28066-8b0090c3",
    ),
}
GATES = {
    "yjs": "HQ Yjs new duplication 20261122",
    "fastapi": "HQ FastAPI new duplication 20261122",
}
RECEIPT = Path(__file__).with_name("community-new-duplication-20261122.json")


def check(ok, message):
    if not ok:
        raise ValueError(message)


def read(path):
    return json.loads(path.read_bytes())


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check_status(status, values, baseline):
    check(
        status["period"]["mode"] == "SPECIFIC_ANALYSIS"
        and status["period"]["parameter"] == baseline,
        "incorrect gate period",
    )
    (condition,) = status["conditions"]
    check(
        (condition["metricKey"], condition["comparator"], condition["errorThreshold"])
        == (METRIC, "GT", "3"),
        "invalid gate condition",
    )
    total, duplicates, density = (
        int(values["new_lines"]),
        int(values["new_duplicated_lines"]),
        float(values[METRIC]),
    )
    check(
        0 <= duplicates <= total
        and total > 0
        and isclose(100 * duplicates / total, density, abs_tol=0.00005),
        "inconsistent reference density",
    )
    check(float(condition["actualValue"]) == density, "gate differs from measure")
    ignored = density > 3 and total < 20
    verdict = "ERROR" if density > 3 and not ignored else "OK"
    check(
        status["ignoredConditions"] is ignored
        and verdict == condition["status"] == status["status"],
        "incorrect Community verdict or small-change exception",
    )
    return {
        "new": total,
        "duplicated": duplicates,
        "density": density,
        "status": verdict,
        "ignored": ignored,
    }


def verify_analysis(folder, project, revision, path):
    task = read(folder / "compute-engine.json")["task"]
    pin = read(folder / "confirmed.json")
    check(
        (task["type"], task["status"], task["componentKey"])
        == ("REPORT", "SUCCESS", project),
        "unsuccessful or wrong compute task",
    )
    check(
        (task["id"], task["analysisId"], revision)
        == (pin["computeId"], pin["analysisId"], pin["revision"]),
        "wrong analysis binding",
    )
    execution = read(folder / "scanner-execution.json")
    log = (folder / "scanner.stdout").read_bytes()
    check(
        execution["exit_code"] == 0
        and execution["status"] == "completed"
        and execution["stdout_sha256"] == sha(log)
        and execution["stderr_sha256"] == sha((folder / "scanner.stderr").read_bytes()),
        "invalid scanner execution",
    )
    check(
        SCANNER in execution["argv"]
        and ("SonarQube Community Build " + SERVER).encode() in log
        and task["id"].encode() in log,
        "incorrect reference environment or task",
    )
    expected = {
        "sonar.projectKey": project,
        "sonar.scm.revision": revision,
        "sonar.projectVersion": revision,
        "sonar.sources": path,
        "sonar.scm.provider": "git",
    }
    for key, value in expected.items():
        check(
            [a for a in execution["argv"] if a.startswith("-D" + key + "=")]
            == ["-D" + key + "=" + value],
            "wrong scanner scope or revision",
        )
    return pin


def capture_digest(folder):
    raw = [
        "../gate.json",
        "assigned.json",
        "inputs.json",
        "result.json",
        "measures.json",
        "candidate/period.json",
    ]
    raw.extend(
        f"{stage}/{filename}"
        for stage in ("base", "candidate")
        for filename in (
            "compute-engine.json",
            "confirmed.json",
            "scanner-execution.json",
            "scanner.stdout",
            "scanner.stderr",
        )
    )
    hashes = {name: sha((folder / name).read_bytes()) for name in sorted(raw)}
    return sha(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode())


def capture_case(folder, repo):
    path = read(folder / "inputs.json")["path"]
    result = read(folder / "result.json")
    project = f"hq-{repo}-duplication-20261122-{folder.name}"
    params = read(folder / "inputs.json")
    check(result["project"] == project and result["source"] == params, "wrong result")
    key = "-".join(
        (sha(path.encode())[:6], params["base"][:8], params["candidate"][:8])
    )
    check(key == folder.name, "case identity differs")
    gate = read(folder.parent / "gate.json")
    assignment = read(folder / "assigned.json")["qualityGate"]
    check(
        assignment == {"name": GATES[repo], "default": False}
        and gate["name"] == GATES[repo]
        and gate["isBuiltIn"] is False
        and gate["isDefault"] is False,
        "wrong assigned gate",
    )
    (condition,) = gate["conditions"]
    check(
        (condition["metric"], condition["op"], condition["error"])
        == (METRIC, "GT", "3"),
        "wrong assigned gate condition",
    )
    pins = {
        s: verify_analysis(folder / s, project, params[s], path)
        for s in ("base", "candidate")
    }
    check(
        pins["base"] == result["baseline"] and pins["candidate"] == result["candidate"],
        "base/candidate receipt differs",
    )
    period = read(folder / "candidate/period.json")
    check(
        (period["projectKey"], period["branchKey"], period["type"], period["value"])
        == (project, "main", "SPECIFIC_ANALYSIS", pins["base"]["analysisId"]),
        "wrong selected baseline",
    )
    component = read(folder / "measures.json")["component"]
    values = {m["metric"]: m.get("period", m)["value"] for m in component["measures"]}
    check(
        component["key"] == project
        and values == result["measures"]
        and len(values) == len(component["measures"]),
        "wrong project measures",
    )
    reference = check_status(result["gate"], values, period["value"])
    return {
        "repo": repo,
        "project": project,
        "path": path,
        **{stage: {**pin, "ce_status": "SUCCESS"} for stage, pin in pins.items()},
        "capture_sha256": capture_digest(folder),
        "assignment_default": assignment["default"],
        "period_type": period["type"],
        "period_branch": period["branchKey"],
        "gate": assignment["name"],
        "condition_id": condition["id"],
        "period": period["value"],
        "reference": reference,
    }


def capture_reference(root):
    return [
        capture_case(root / ("live" if repo == "yjs" else "fastapi-live") / ident, repo)
        for repo, ids in IDS.items()
        for ident in ids
    ]
