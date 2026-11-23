"""Verify project gate assignment on two pinned Redux revisions with a real CLI and service."""

import argparse
import copy
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
import tempfile

from community_hotspot_replay import (
    BASE,
    HEAD,
    SOURCE,
    DIGESTS,
    CONDITION,
    check_gate,
    git,
    scan,
    reject,
)
from public_coverage_gate_replay import check

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from smoke_cli_service import request, running_service
from service_project_snapshot import snapshot

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"


def cfg(metric, threshold, scope="overall", operator="lte"):
    return {
        "schema_version": 1,
        "conditions": [
            {
                "scope": scope,
                "metric": metric,
                "operator": operator,
                "threshold": threshold,
            }
        ],
    }


STRICT = cfg("files", 0)
LOOSE = cfg("files", 2)
REVIEW = cfg(CONDITION["metric"], 100, "new_code", "gte")


def reports(scanner, base, head, work):
    for root, rev in ((base, BASE), (head, HEAD)):
        check(
            git(root, "rev-parse", "HEAD") == rev
            and hashlib.sha256((root / SOURCE).read_bytes()).hexdigest()
            == DIGESTS[rev],
            "wrong public source",
        )
    check(git(head, "rev-parse", "HEAD^") == BASE, "wrong base")
    path = work / "weak.json"
    path.write_text(json.dumps(cfg("files", 99)))
    baseline = work / "base.native.json"
    b = scan(
        scanner,
        work,
        base,
        "weak-base",
        ["--quality-gate", path, "--write-baseline", baseline],
        0,
    )
    h = scan(scanner, work, head, "weak-head", ["--quality-gate", path], 0)
    absent = scan(scanner, work, head, "no-gate", [], 0)
    reviewed = scan(
        scanner, work, head, "baseline-no-gate", ["--baseline", baseline], 0
    )
    return b, h, absent, reviewed


class Client:
    def __init__(self, port, tokens):
        self.port = port
        self.tokens = tokens

    def call(self, role, path, body=None, method=None):
        return request(
            self.port, self.tokens[role], "/smoke" + path, body, method=method
        )

    def assign(self, role, version, config):
        return self.call(
            role,
            "/gate-policy",
            {"schema_version": 1, "expected_version": version, "config": config},
            "PUT",
        )

    def ingest(self, report, rev, branch="main", role="scanner"):
        return self.call(
            role,
            "/analyses",
            {
                "schema_version": 1,
                "branch": branch,
                "commit": rev,
                "analyzed_at": "2026-11-22T00:00:00Z",
                "report": report,
            },
        )

    def current(self, rid):
        return self.call("reader", f"/analyses/{rid}/gate")


def verify(row, version, status, threshold):
    check(
        row["gate_policy_version"] == version
        and row["gate"]["status"] == status
        and row["gate"]["conditions"][0]["threshold"] == threshold,
        "incorrect assigned gate",
    )


def ci(receipt, expected, *, commit=None):
    row = receipt["analysis"]
    proc = subprocess.run(
        [
            sys.executable,
            SCRIPTS / "check_project_gate.py",
            "--project",
            "smoke",
            "--branch",
            row["branch"],
            "--commit",
            commit or row["commit"],
        ],
        input=json.dumps(receipt),
        text=True,
        capture_output=True,
        timeout=15,
    )
    check(
        proc.returncode == expected,
        f"CI expected {expected}, got {proc.returncode}: {proc.stdout} {proc.stderr}",
    )


def policy_controls(c, b, h, absent):
    with_base = c.ingest(b, BASE, "unassigned")
    ci(with_base, 2)
    check(
        "gate_policy_version" not in with_base["analysis"]
        and with_base["analysis"]["gate"]["status"] == "pass",
        "legacy result changed",
    )
    check(
        c.call("reader", "/gate-policy") == {"policy": None}, "unexpected assigned gate"
    )
    for role in ("reader", "reviewer", "scanner", "foreign"):
        reject(partial(c.assign, role, 0, STRICT), 403)
    for role in ("reader", "reviewer", "foreign"):
        reject(partial(c.ingest, b, BASE, "denied", role), 403)
    reject(partial(c.call, "foreign", "/gate-policy"), 403)
    assert c.assign("admin", 0, STRICT)["policy"]["version"] == 1
    reject(partial(c.assign, "admin", 0, LOOSE), 409)
    reject(partial(c.assign, "admin", 1, {"schema_version": 1, "conditions": []}), 400)
    strict = c.ingest(h, HEAD)
    ci(strict, 1)
    row = strict["analysis"]
    verify(row, 1, "fail", 0)
    rid = row["id"]
    detail = c.call("reader", f"/analyses/{rid}")["analysis"]
    check(
        detail["report"]["assessment"]["gate"]["status"] == "pass"
        and c.current(rid)["status"] == "fail",
        "weak upload won",
    )
    omitted = c.ingest(absent, HEAD, "omitted")
    ci(omitted, 1)
    verify(omitted["analysis"], 1, "fail", 0)
    check(
        c.current(omitted["analysis"]["id"])["status"] == "fail",
        "omitting gate bypassed policy",
    )
    assert c.assign("admin", 1, LOOSE)["policy"]["version"] == 2
    fresh = c.ingest(b, BASE)
    verify(fresh["analysis"], 2, "pass", 2)
    ci(fresh, 0)
    ci(fresh, 2, commit=HEAD)
    old = c.ingest(h, HEAD)
    assert old["idempotent"]
    verify(old["analysis"], 1, "fail", 0)
    return with_base["analysis"]["id"], rid


def review_controls(c, absent, reviewed):
    assert c.assign("admin", 2, REVIEW)["policy"]["version"] == 3
    missing = c.ingest(absent, HEAD, "missing")
    ci(missing, 2)
    verify(missing["analysis"], 3, "unavailable", 100)
    check(
        c.current(missing["analysis"]["id"])["status"] == "unavailable",
        "missing evidence passed",
    )
    row = c.ingest(reviewed, HEAD, "reviews")["analysis"]
    rid = row["id"]
    check_gate(row["gate"], 0, "fail")
    findings = c.call("reader", f"/analyses/{rid}/findings")["findings"]
    items = sorted(
        (f for f in findings if f["kind"] == "hotspot"),
        key=lambda f: f["range"]["start"]["line"],
    )
    check(
        [f["range"]["start"]["line"] for f in items] == [8, 9],
        "wrong review population",
    )

    def review(role, item):
        return c.call(
            role,
            "/reviews",
            {
                "schema_version": 1,
                "analysis_id": rid,
                "identity": item["identity"],
                "kind": "hotspot",
                "state": "safe",
                "reason": "pinned Redux qualification",
                "expected_version": 0,
            },
        )

    reject(partial(review, "scanner", items[0]), 403)
    for item, expected in zip(items, (50, 100), strict=True):
        review("reviewer", item)
        check_gate(c.current(rid), expected, "pass" if expected == 100 else "fail")
    check_gate(c.call("reader", f"/analyses/{rid}")["analysis"]["gate"], 0, "fail")
    return rid


def restore_controls(c, backup):
    corrupt = copy.deepcopy(backup)
    corrupt["analyses"][0]["gate_policy_version"] = 999
    reject(partial(c.call, "admin", "/restore", corrupt), 409)
    call = partial(c.call, "admin", "/restore")
    # A legitimate archive with fewer analyses can bootstrap the empty destination.
    partial_backup = copy.deepcopy(backup)
    omitted = next(a for a in partial_backup["analyses"] if a["branch"] == "omitted")
    partial_backup["analyses"].remove(omitted)
    partial_backup["findings"] = [
        f for f in partial_backup["findings"] if f["analysis_id"] != omitted["id"]
    ]
    call(partial_backup)
    call(partial_backup)
    forged = copy.deepcopy(backup)
    next(a for a in forged["analyses"] if a["branch"] == "omitted").pop(
        "gate_policy_version"
    )
    reject(partial(call, forged), 409)
    reject(partial(call, backup), 409)
    conflicting = copy.deepcopy(partial_backup)
    conflicting["gate_policies"][0]["config"] = LOOSE
    reject(partial(call, conflicting), 409)


def check_recovery(start, tokens, work):
    with start(work) as port:
        c = Client(port, tokens)
        backup = c.call("admin", "/export")
    for name in ("controls", "restored"):
        (work / name).mkdir()
    with start(work / "controls") as port:
        restore_controls(Client(port, tokens), backup)
    with start(work / "restored") as port:
        c = Client(port, tokens)
        c.call("admin", "/restore", backup)
        c.call("admin", "/restore", backup)
        rows = c.call("reader", "/analyses")["analyses"]
        target = next(a for a in rows if a["branch"] == "main" and a["commit"] == HEAD)
        verify(target, 1, "fail", 0)
        check(c.current(target["id"])["status"] == "fail", "restore lost policy")
        check(
            c.call("reader", "/gate-policy")["policy"]["version"] == 3,
            "restore lost history",
        )
        check_gate(
            c.current(next(a["id"] for a in rows if a["branch"] == "reviews")),
            100,
            "pass",
        )
    archive = work / "project.sqlite"
    rebuilt = work / "rebuilt.sqlite"
    record = snapshot(work / "service.sqlite3", archive, "smoke")
    snapshot(archive, rebuilt, "smoke", record["sha256"])
    with sqlite3.connect(rebuilt) as db:
        assert (
            db.execute("SELECT COUNT(*) FROM project_gate_policies").fetchone()[0] == 3
        )
        assert (
            db.execute(
                "SELECT gate_policy_version FROM analyses WHERE branch='main' AND commit_sha=?",
                [HEAD],
            ).fetchone()[0]
            == 1
        )


def concurrent_bindings(start, tokens, work, report):
    # These services open separate SQLite connections to one project database.
    root = work / "concurrent"
    root.mkdir()
    with start(root) as a, start(root) as b, ThreadPoolExecutor(4) as pool:
        left, right = Client(a, tokens), Client(b, tokens)
        left.assign("admin", 0, STRICT)  # Assign before the project's first upload.
        writers = [pool.submit(c.assign, "admin", 1, LOOSE) for c in (left, right)]
        uploads = [pool.submit(c.ingest, report, HEAD) for c in (left, right)]

        def accepted(writer):
            if (err := writer.exception()) is not None:
                check(
                    isinstance(err, RuntimeError) and "HTTP 409:" in str(err),
                    "unexpected concurrent policy write result",
                )
                return False
            return writer.result()["policy"]["version"] == 2

        commits = sum(accepted(w) for w in writers)
        check(commits == 1, "competing writers both committed")
        replies = [f.result() for f in uploads]
        check(
            sorted(r["idempotent"] for r in replies) == [False, True]
            and replies[0]["analysis"] == replies[1]["analysis"],
            "concurrent scanner replay changed the binding",
        )
        row = replies[0]["analysis"]
        expected = {1: ("fail", 0), 2: ("pass", 2)}[row["gate_policy_version"]]
        verify(row, row["gate_policy_version"], *expected)
        check(
            left.current(row["id"])["status"] == expected[0],
            "live gate used a different revision",
        )


def run(scanner, service, base, head, work):
    b, h, absent, reviewed = reports(scanner, base, head, work)
    tokens = {
        r: secrets.token_urlsafe(32)
        for r in ("admin", "scanner", "reader", "reviewer", "foreign")
    }
    creds = [
        {
            "user_id": r,
            "token": tokens[r],
            "projects": ({"else": "admin"} if r == "foreign" else {"smoke": r}),
        }
        for r in tokens
        if r != "admin"
    ]

    def start(root):
        return running_service(service, root, tokens["admin"], extra_credentials=creds)

    with start(work) as port:
        c = Client(port, tokens)
        unassigned, strict = policy_controls(c, b, h, absent)
        reviews = review_controls(c, absent, reviewed)
    with start(work) as port:
        c = Client(port, tokens)
        check(
            c.call("reader", "/gate-policy")["policy"]["version"] == 3,
            "lost policy on restart",
        )
        check(
            c.current(strict)["status"] == "fail"
            and c.current(unassigned)["status"] == "pass",
            "historical verdict changed",
        )
        check_gate(c.current(reviews), 100, "pass")
    check_recovery(start, tokens, work)
    concurrent_bindings(start, tokens, work, h)
    return {
        "project": "reduxjs/redux",
        "source": SOURCE,
        "revisions": [BASE, HEAD],
        "source_sha256": DIGESTS,
        "scanner_sha256": hashlib.sha256(scanner.read_bytes()).hexdigest(),
        "service_sha256": hashlib.sha256(service.read_bytes()).hexdigest(),
        "unassigned": "scanner pass",
        "assigned_v1": "scanner pass, service fail (1 file > 0)",
        "omitted_scanner_gate": "service fail",
        "assigned_v2": "service pass (1 file <= 2)",
        "replayed_v1": "unchanged failure",
        "missing_baseline_v3": "unavailable",
        "assigned_review_percent": [0, 50, 100],
        "immutable_review_percent": 0,
        "after_restart_review_percent": 100,
        "ci_exit": {
            "assigned_pass": 0,
            "weak_scanner_pass": 1,
            "omitted_gate": 1,
            "unassigned": 2,
            "missing_baseline": 2,
            "wrong_revision": 2,
        },
        "two_service_processes": "one accepted writer; duplicate ingest kept one policy and analysis",
        "restart": True,
        "json_restore": True,
        "project_sqlite_snapshot_restore": True,
        "governed_restore_rejects_unknown_analyses": True,
        "reader_reviewer_scanner_and_foreign_policy_write": "403",
        "scanner_review": "403",
        "stale_assignment": "409",
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for key in ("scanner", "service", "base", "head", "output"):
        p.add_argument("--" + key, type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=a.output.resolve()) as tmp:
        receipt = run(
            *(x.resolve(strict=True) for x in (a.scanner, a.service, a.base, a.head)),
            Path(tmp),
        )
    (a.output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
