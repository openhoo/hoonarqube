"""Replay Redux's two new hotspots through the real scanner and review service."""

import argparse
import copy
import hashlib
import json
import secrets
import subprocess
import sys
import tempfile
from functools import partial
from pathlib import Path

from public_coverage_gate_replay import check

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from smoke_cli_service import request, running_service

BASE = "0b6d794effa9da5080bfb4c6865a324357b85018"
HEAD = "e6f6c7da7b39ed46273d05d150cf1f578973ac3c"
SOURCE = "src/utils/actionTypes.js"
DIGESTS = {
    BASE: "8c9eef6d0b9ceae64357de9e01cb4df0f3e826990017f20b2dfc5589d6f54388",
    HEAD: "505b660b824a71a0486a18d32d4b3bfb9f243262048d77aa6cb20dcb89c2744c",
}
CONDITION = {
    "scope": "new_code",
    "metric": "security_hotspots_reviewed",
    "operator": "gte",
    "threshold": 100,
}


def git(root, *args):
    return subprocess.check_output(["git", "-C", root, *args], text=True).strip()


def scan(binary, work, src, name, args, exit_code):
    run = subprocess.run(
        [
            binary,
            "analyze",
            SOURCE,
            "--json",
            "--profile",
            "sonar-parity",
            "--assessment",
            *args,
        ],
        cwd=src,
        capture_output=True,
        timeout=60,
    )
    check(
        run.returncode == exit_code,
        f"{name}: expected {exit_code}, got {run.returncode}: {run.stderr[:500]!r}",
    )
    report = json.loads(run.stdout)
    check(
        report["project"]["complete"]
        and [f["path"] for f in report["files"]] == [SOURCE],
        "wrong source scope",
    )
    (work / (name + ".json")).write_bytes(run.stdout)
    return report


def reject(request, code):
    try:
        request()
    except RuntimeError as error:
        check(f"HTTP {code}:" in str(error), f"expected HTTP {code}: {error}")
    else:
        raise ValueError(f"expected HTTP {code}")


def check_gate(gate, actual, condition_status):
    c = gate["conditions"]
    check(
        len(c) == 1
        and c[0]["metric"] == CONDITION["metric"]
        and c[0]["actual"] == actual
        and c[0]["status"] == condition_status,
        f"unexpected condition: {c}",
    )
    expected = {
        "no_value": "pass",
        "unavailable": "unavailable",
        "pass": "pass",
        "fail": "fail",
    }[condition_status]
    check(gate["status"] == expected, f"unexpected aggregate: {gate}")
    return {"actual": actual, "condition": condition_status, "gate": gate["status"]}


def scan_pair(scanner, base, head, work):
    for root, rev in ((base, BASE), (head, HEAD)):
        check(git(root, "rev-parse", "HEAD") == rev, "wrong Git revision")
        check(
            hashlib.sha256((root / SOURCE).read_bytes()).hexdigest() == DIGESTS[rev],
            "wrong source bytes",
        )
    check(git(head, "rev-parse", "HEAD^") == BASE, "not adjacent revisions")
    gate_path = work / "gate.json"
    gate_path.write_text(json.dumps({"schema_version": 1, "conditions": [CONDITION]}))
    baseline = work / "base.native.json"
    scan(scanner, work, base, "base", ["--write-baseline", baseline], 0)
    args = ["--baseline", baseline, "--quality-gate", gate_path]
    empty = scan(scanner, work, base, "unchanged", args, 0)
    new = scan(scanner, work, head, "candidate", args, 1)
    missing = scan(scanner, work, head, "missing", ["--quality-gate", gate_path], 2)
    return baseline, empty, new, missing


def service_clients(service, work):
    roles = {
        role: secrets.token_urlsafe(32) for role in ["admin", "reviewer", "reader"]
    }
    cred = [
        {"user_id": role, "token": roles[role], "projects": {"smoke": role}}
        for role in ("reviewer", "reader")
    ]

    def start():
        return running_service(service, work, roles["admin"], extra_credentials=cred)

    def ingest(port, report, branch, sha):
        return request(
            port,
            roles["admin"],
            "/smoke/analyses",
            {
                "schema_version": 1,
                "analyzed_at": "2026-11-22T00:00:00Z",
                "branch": branch,
                "commit": sha,
                "report": report,
            },
        )["analysis"]

    return start, ingest, roles


def review_lifecycle(start, ingest, roles, empty, new, missing, states):
    with start() as port:
        empty_row = ingest(port, empty, "main", BASE)
        check_gate(
            request(port, roles["reader"], f"/smoke/analyses/{empty_row['id']}/gate"),
            None,
            "no_value",
        )
        check_gate(ingest(port, missing, "missing", HEAD)["gate"], None, "unavailable")
        row = ingest(port, new, "main", HEAD)
        detail = f"/smoke/analyses/{row['id']}"

        def live():
            return request(port, roles["reader"], detail + "/gate")

        findings = request(port, roles["reader"], detail + "/findings")["findings"]
        items = sorted(
            (f for f in findings if f["kind"] == "hotspot"),
            key=lambda f: f["range"]["start"]["line"],
        )
        check(
            [
                (f["rule_key"], f["range"]["start"]["line"], f["ambiguous"])
                for f in items
            ]
            == [("javascript:S2245", 8, False), ("javascript:S2245", 9, False)],
            f"wrong reviewed population: {[(f['rule_key'], f['range'], f['ambiguous']) for f in items]}",
        )

        def review(i, state, version, role="reviewer"):
            return request(
                port,
                roles[role],
                "/smoke/reviews",
                {
                    "schema_version": 1,
                    "analysis_id": row["id"],
                    "identity": items[i]["identity"],
                    "kind": "hotspot",
                    "state": state,
                    "reason": "public qualification",
                    "expected_version": version,
                },
            )

        reject(lambda: review(0, "safe", 0, "reader"), 403)
        states["reader_denied"] = check_gate(live(), 0, "fail")
        review(0, "safe", 0)
        reject(lambda: review(0, "safe", 0), 409)
        states["one_reviewed"] = check_gate(live(), 50, "fail")
        review(1, "confirmed_risk", 0)
        states["both_reviewed"] = check_gate(live(), 100, "pass")
        other = ingest(port, new, "other", HEAD)
        states["other_branch"] = check_gate(
            request(port, roles["reader"], f"/smoke/analyses/{other['id']}/gate"),
            0,
            "fail",
        )
        forged = copy.deepcopy(new)
        forged["assessment"]["gate"] = live()
        reject(lambda: ingest(port, forged, "forged", HEAD), 409)
        forged["assessment"]["gate"] = empty["assessment"]["gate"]
        reject(lambda: ingest(port, forged, "fake-empty", HEAD), 409)
    with start() as port:
        states["after_restart"] = check_gate(live(), 100, "pass")
        mutation = review(0, "to_review", 1)
        check(
            mutation["review"]["updated_by"] == "reviewer"
            and mutation["review"]["version"] == 2,
            "missing authorized history",
        )
        states["reopened"] = check_gate(live(), 50, "fail")
        states["immutable_scan"] = check_gate(
            request(port, roles["reader"], detail)["analysis"]["gate"], 0, "fail"
        )
        backup = request(port, roles["admin"], "/smoke/export")
    return backup, other["id"]


def restore_legacy(service, work, roles, backup, other_id):
    # Pre-fix backups marked repeated rule/message pairs ambiguous at distinct
    # ranges. Use the untouched other branch so it has no authorized reviews.
    target = work / "legacy-restore"
    target.mkdir()
    legacy = copy.deepcopy(backup)
    old = [f for f in legacy["findings"] if f["analysis_id"] == other_id]
    counts = {}
    for f in old:
        key = (f["path"], f["rule_key"], f["message"])
        counts[key] = counts.get(key, 0) + 1
    for f in old:
        f["ambiguous"] |= counts[(f["path"], f["rule_key"], f["message"])] > 1
    with running_service(service, target, roles["admin"]) as port:
        tampered = copy.deepcopy(legacy)
        unique = next(
            f
            for f in tampered["findings"]
            if f["analysis_id"] == other_id and not f["ambiguous"]
        )
        unique["ambiguous"] = True
        reject(lambda: request(port, roles["admin"], "/smoke/restore", tampered), 409)
        request(port, roles["admin"], "/smoke/restore", legacy)
        restored = request(
            port, roles["admin"], f"/smoke/analyses/{other_id}/findings"
        )["findings"]
        check(
            [f["ambiguous"] for f in restored if f["kind"] == "hotspot"]
            == [True, True],
            "legacy ambiguity flags not preserved",
        )


def mapped_replay(scanner, work, base, head, baseline, start, ingest, roles):
    mapped_gate = work / "mapped-gate.json"
    names = [
        "community_26_9_violations",
        "community_26_9_security_hotspots_reviewed",
    ]
    mapped_gate.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "conditions": [
                    {
                        "scope": "new_code",
                        "metric": names[0],
                        "operator": "lte",
                        "threshold": 0,
                    },
                    {**CONDITION, "metric": names[1]},
                ],
            }
        )
    )

    def verdict(report):
        return [(c["metric"], c["actual"], c["status"]) for c in report["conditions"]]

    pinned = {}
    for label, checkout, rev, extra, code, values in [
        (
            "unchanged",
            base,
            BASE,
            ["--baseline", baseline],
            0,
            [(0, "pass"), (None, "no_value")],
        ),
        (
            "candidate",
            head,
            HEAD,
            ["--baseline", baseline],
            1,
            [(2, "fail"), (None, "no_value")],
        ),
        (
            "missing",
            head,
            HEAD,
            [],
            2,
            [(None, "unavailable"), (None, "unavailable")],
        ),
    ]:
        report = scan(
            scanner,
            work,
            checkout,
            "mapped-" + label,
            [*extra, "--quality-gate", mapped_gate],
            code,
        )
        expected = [
            (key, value, state)
            for key, (value, state) in zip(names, values, strict=True)
        ]
        decision = report["assessment"]["gate"]
        check(
            verdict(decision) == expected,
            f"{label}: wrong 26.9 mapped decision: {decision}",
        )
        with start() as port:
            row = ingest(port, report, "mapped-" + label, rev)
            live_gate = request(
                port, roles["reader"], f"/smoke/analyses/{row['id']}/gate"
            )
            check(
                verdict(live_gate) == expected == verdict(row["gate"]),
                "mapped HTTP/CLI mismatch",
            )
            if label == "candidate":
                # Retaining the claimed gate after removing its supporting profile
                # evidence must be rejected; there is no language-only fallback.
                for mutation in ("absent", "unknown", "partial"):
                    wrong = copy.deepcopy(report)
                    if mutation == "absent":
                        del wrong["parity"]
                    elif mutation == "unknown":
                        wrong["parity"]["reference"]["profile"] = "custom"
                    else:
                        wrong["parity"]["active_rules"].pop()
                    reject(
                        partial(ingest, port, wrong, "unqualified-" + mutation, rev),
                        409,
                    )
        pinned[label] = {
            "exit_code": code,
            "status": decision["status"],
            "conditions": verdict(decision),
        }
    return pinned


def replay(scanner, service, base, head, work, *, mapped=False):
    baseline, empty, new, missing = scan_pair(scanner, base, head, work)
    receipt = {
        "repo": "reduxjs/redux",
        "base": BASE,
        "head": HEAD,
        "path": SOURCE,
        "sha256": DIGESTS,
        "scanner_sha256": hashlib.sha256(scanner.read_bytes()).hexdigest(),
        "service_sha256": hashlib.sha256(service.read_bytes()).hexdigest(),
        "rule": "javascript:S2245",
        "states": {},
    }
    states = receipt["states"]
    for name, report, sha, actual, status in [
        ("unchanged", empty, BASE, None, "no_value"),
        ("unreviewed", new, HEAD, 0, "fail"),
        ("missing", missing, HEAD, None, "unavailable"),
    ]:
        check(
            report["assessment"]["context"]["source_revision"] == sha,
            "wrong report revision",
        )
        states[name] = check_gate(report["assessment"]["gate"], actual, status)

    start, ingest, roles = service_clients(service, work)
    backup, other_id = review_lifecycle(
        start, ingest, roles, empty, new, missing, states
    )
    restore_legacy(service, work, roles, backup, other_id)
    receipt["legacy_backup_ambiguity_preserved"] = True
    if mapped:
        receipt["community_26_9_mapping"] = mapped_replay(
            scanner, work, base, head, baseline, start, ingest, roles
        )
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("scanner", "service", "base", "head", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument(
        "--mapped", action="store_true", help="also qualify the 26.9 profile aliases"
    )
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=args.output.resolve()) as tmp:
        work = Path(tmp).resolve()
        receipt = replay(
            *(
                p.resolve(strict=True)
                for p in (args.scanner, args.service, args.base, args.head)
            ),
            work,
            mapped=args.mapped,
        )
        artifacts = ["base", "candidate", "unchanged", "missing"]
        if args.mapped:
            artifacts.extend(["mapped-unchanged", "mapped-candidate", "mapped-missing"])
        for name in artifacts:
            (args.output / (name + ".json")).write_bytes(
                (work / (name + ".json")).read_bytes()
            )
    (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
