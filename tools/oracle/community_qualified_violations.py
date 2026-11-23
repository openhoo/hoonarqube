"""Replay three captured Community 26.9 violation gates against complete local histories."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import tempfile

from community_detector_controls import MANIFEST, required_rules
from community_scm_period import check, descriptor, git, read, run_case
from project_gate_policy_replay import Client, ci, running_service
from public_corpus_prepare import GIT_ENV

METRICS = ("community_26_9_violations", "community_26_9_qualified_violations")
CONDITIONS = [
    {"scope": "new_code", "metric": m, "operator": "lte", "threshold": 0}
    for m in METRICS
]
DIGEST = "community_detector_controls_sha256"
EXPECTED = {
    "missing_js": ("javascript", 420, [("javascript:S7724", 470)], 2),
    "go_violation": ("go", 22, [("go:S3776", 121)], 1),
    "go_clean": ("go", 22, [], 0),
}


def object_bytes(repo, *args):
    return subprocess.check_output(
        ["git", "-c", "core.hooksPath=/dev/null", "-C", repo, *args],
        env=GIT_ENV,
        timeout=30,
    )


def verify_sources(repo, case):
    base, head = case["base"], case["head"]
    check(
        object_bytes(repo, "rev-parse", head["revision"] + "^").decode().strip()
        == base["revision"],
        "wrong parent",
    )
    check(base["path"] == head["path"], "sources differ")
    for scan in (base, head):
        check(
            scan["reference_files"] == [scan["path"]],
            "wrong reference source inventory",
        )
        rev = scan["revision"]
        check(
            object_bytes(repo, "rev-parse", rev + "^{tree}").decode().strip()
            == scan["tree"],
            "wrong tree",
        )
        blob = object_bytes(repo, "show", rev + ":" + scan["path"])
        check(hashlib.sha256(blob).hexdigest() == scan["sha256"], "wrong source bytes")
        check(scan["ce_status"] == "SUCCESS", "reference analysis did not complete")


def reference(case, count, expected):
    base, head = case["base"], case["head"]
    profile = case["profile"]
    check(
        profile["name"] == "Sonar way"
        and profile["isBuiltIn"]
        and profile["activeRuleCount"] == count
        and profile["language"] == ("js" if count == 420 else "go"),
        "wrong reference profile",
    )
    check(
        not base["new_issues"] and base["gate"]["conditions"] == [],
        "unexpected baseline findings",
    )
    check(
        [(i["rule"], i["line"]) for i in head["new_issues"]] == expected,
        "wrong reference issues",
    )
    gate = head["gate"]
    check(
        gate["status"] == ("ERROR" if expected else "OK")
        and not gate["ignoredConditions"],
        "wrong reference verdict",
    )
    check(
        gate["conditions"]
        == [
            {
                "status": gate["status"],
                "metricKey": "new_violations",
                "comparator": "GT",
                "errorThreshold": "0",
                "actualValue": str(len(expected)),
            }
        ],
        "wrong reference condition",
    )
    return descriptor(gate["period"], base["analysis_id"], base["revision"])


def findings(report, lang):
    files = {f["path"]: f["issues"] for f in report["files"]}
    active = required_rules()
    found = []
    for row in report["assessment"]["new_code"]["findings"]:
        issue = files[row["path"]][row["issue_index"]]
        if row["status"] == "new" and (lang, issue["rule_key"]) in active:
            found.append((issue["rule_key"], issue["range"]["start"]["line"]))
    return found


def decisions(gate, expected):
    conds = gate["conditions"]
    check([c["metric"] for c in conds] == list(METRICS), "wrong metrics")
    check([(c["status"], c["actual"]) for c in conds] == expected, "wrong gate values")
    return conds


def candidate(cli, work, repo, case):
    label = case["id"]
    lang, count, expected, code = EXPECTED[label]
    verify_sources(repo, case)
    selection = reference(case, count, expected)
    head, base = case["head"], case["base"]
    status, report, _ = run_case(
        cli,
        repo,
        work,
        [head["path"]],
        base["revision"],
        head["revision"],
        selection,
        CONDITIONS,
    )
    check(status == code, "wrong CLI exit")
    assessment = report["assessment"]
    period = assessment["new_code"]
    check(
        [f["path"] for f in report["files"]] == [head["path"]] and period["lines"],
        "wrong scope or empty period",
    )
    measured_lines = sum(len(row["lines"]) for row in period["lines"])
    check(
        measured_lines == {"missing_js": 5, "go_violation": 86, "go_clean": 19}[label],
        "SCM membership changed",
    )
    if label != "missing_js":
        fingerprint = hashlib.sha256(MANIFEST.read_bytes()).hexdigest()
        check(
            assessment["context"].get(DIGEST)
            == period["reference_context"].get(DIGEST)
            == fingerprint,
            "complete scans have no matching control digest",
        )
    native = [] if label == "missing_js" else expected
    check(findings(report, lang) == native, "native active-rule findings differ")
    legacy = ("fail" if native else "pass", len(native))
    strict = ("unavailable", None) if label == "missing_js" else legacy
    conds = decisions(assessment["gate"], [legacy, strict])
    if label == "missing_js":
        absent, unproved = conds[1]["diagnostic"].split("; ")
        check(
            "absent from native profile" in absent
            and "javascript:S7724" in absent
            and "without verified detector controls" in unproved,
            "wrong blocking detector",
        )
    return report, [legacy, strict]


def with_service(binary, work, results):
    tokens = {
        role: secrets.token_urlsafe(32) for role in ["admin", "reader", "scanner"]
    }
    creds = [
        {"user_id": r, "token": tokens[r], "projects": {"smoke": r}}
        for r in ("reader", "scanner")
    ]

    def start():
        return running_service(binary, work, tokens["admin"], extra_credentials=creds)

    saved = {}
    with start() as port:
        c = Client(port, tokens)
        c.assign("admin", 0, {"schema_version": 1, "conditions": CONDITIONS})
        for name, (report, verdicts) in results.items():
            record = submit(c, name, report, verdicts)
            saved[name] = (record["id"], verdicts)
        negative_controls(c, results["go_clean"][0])
    with start() as port:
        c = Client(port, tokens)
        for rid, verdicts in saved.values():
            decisions(c.current(rid), verdicts)


def submit(client, branch, source, expected):
    report = copy.deepcopy(source)
    assessment = report["assessment"]
    assessment.pop("gate", None)
    receipt = client.ingest(report, assessment["context"]["source_revision"], branch)
    row = receipt["analysis"]
    check(row["gate_policy_version"] == 1, "service did not apply assigned policy")
    decisions(row["gate"], expected)
    ci(receipt, {"pass": 0, "fail": 1, "unavailable": 2}[expected[1][0]])
    return row


def negative_controls(client, clean):
    for which in ("candidate", "baseline"):
        for mode in ("missing", "different"):
            report = copy.deepcopy(clean)
            assessment = report["assessment"]
            ctx = (
                assessment["context"]
                if which == "candidate"
                else assessment["new_code"]["reference_context"]
            )
            if mode == "missing":
                del ctx[DIGEST]
            else:
                ctx[DIGEST] = "1" * 64
            row = submit(
                client, which + "-" + mode, report, [("pass", 0), ("unavailable", None)]
            )
            check(
                which + " scanner" in row["gate"]["conditions"][1]["diagnostic"],
                "wrong provenance diagnostic",
            )
    report = copy.deepcopy(clean)
    report["parity"]["completeness"] = "incomplete"
    row = submit(client, "incomplete", report, [("pass", 0), ("unavailable", None)])
    check(
        "complete native parity" in row["gate"]["conditions"][1]["diagnostic"],
        "wrong completeness diagnostic",
    )


def run(args, work):
    ref = read("community-qualified-violations-26.9.json")
    check(ref["server_version"] == "26.9.0.129388", "wrong reference version")
    check(
        ref["quality_gate"] == {"metric": "new_violations", "op": "GT", "error": "0"},
        "wrong reference gate",
    )
    out = {}
    for case in ref["cases"]:
        name = case["id"]
        src = {"go-chi/chi": args.chi, "yjs/yjs": args.yjs}[case["repository"]]
        dest = work / name
        git(
            work,
            "clone",
            "-q",
            "--shared",
            "--no-checkout",
            "--",
            str(src.resolve(strict=True)),
            str(dest),
        )
        out[name] = candidate(args.scanner.resolve(strict=True), work, dest, case)
    check(set(out) == set(EXPECTED), "missing public cases")
    with_service(args.service.resolve(strict=True), work, out)
    return {
        k: {
            "legacy": v[1][0],
            "strict": v[1][1],
            "changed_lines": sum(
                len(x["lines"]) for x in v[0]["assessment"]["new_code"]["lines"]
            ),
        }
        for k, v in out.items()
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("scanner", "service", "yjs", "chi"):
        parser.add_argument("--" + key, type=Path, required=True)
    with tempfile.TemporaryDirectory() as tmp:
        print(json.dumps(run(parser.parse_args(), Path(tmp).resolve()), indent=2))
