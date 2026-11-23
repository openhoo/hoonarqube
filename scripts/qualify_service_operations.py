"""Qualify a local Hoonarqube service against four complete, real CLI reports."""

import argparse
import hashlib
import json
import os
import platform
import secrets
import socket
import sqlite3
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from decimal import Decimal
from http.client import HTTPConnection
from pathlib import Path
from threading import Barrier, Event
from urllib.parse import urlencode

PROJECTS = ("alpha", "beta")
PREFIX = "/api/v1/projects"
CAP = 16 * 1024 * 1024
ROUNDS = 3


def encode(value):
    return json.dumps(value, separators=(",", ":")).encode()


def decode(raw):
    return json.loads(raw, parse_float=Decimal)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def timed(task):
    start = time.monotonic()
    result = task()
    return result, round((time.monotonic() - start) * 1000, 3)


def sql_read(db):
    return sqlite3.connect(db.resolve().as_uri() + "?mode=ro", uri=True)


@contextmanager
def service(binary, database):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    tokens = {
        p + role: secrets.token_urlsafe(24)
        for p in PROJECTS
        for role in ("admin", "reader")
    }
    credentials = [
        {"user_id": p + role, "token": tokens[p + role], "projects": {p: role}}
        for p in PROJECTS
        for role in ("admin", "reader")
    ]
    startup = time.monotonic()
    env = os.environ.copy()
    env.pop("HOONARQUBE_SERVICE_CREDENTIALS_FILE", None)
    with subprocess.Popen(
        [binary],
        cwd=database.parent,
        env={
            **env,
            "HOONARQUBE_SERVICE_BIND": f"127.0.0.1:{port}",
            "HOONARQUBE_SERVICE_DB": str(database),
            "HOONARQUBE_SERVICE_CREDENTIALS": json.dumps(credentials),
            "TOKIO_WORKER_THREADS": "4",
        },
    ) as process:

        def call(
            path="",
            body=None,
            *,
            project="alpha",
            credential=None,
            expected=200,
            method=None,
        ):
            return request(
                port,
                tokens[credential or project + "admin"],
                project,
                path,
                body,
                expected,
                method,
            )

        try:
            while True:
                assert process.poll() is None, f"service exited: {process.returncode}"
                try:
                    request(port, tokens["alphaadmin"], "", "", None, 200)
                    break
                except ConnectionRefusedError:
                    if time.monotonic() - startup > 10:
                        raise
                    time.sleep(0.02)
            yield (
                process,
                call,
                port,
                tokens,
                round((time.monotonic() - startup) * 1000, 3),
            )
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def request(port, token, project, path, body, expected, method=None):
    with closing(HTTPConnection("127.0.0.1", port, timeout=20)) as client:
        client.request(
            method or ("GET" if body is None else "POST"),
            PREFIX + ("/" + project if project else "") + path,
            body,
            {"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        )
        answer = client.getresponse()
        raw = answer.read()
        if expected is None:
            return answer.status, raw
        if answer.status != expected:
            raise RuntimeError(
                f"{project}{path}: HTTP {answer.status}, expected {expected}: "
                f"{raw[:160]!r}"
            )
        return raw


def ingest_bytes(raw, commit):
    return (
        encode(
            {
                "schema_version": 1,
                "branch": "main",
                "commit": commit,
                "analyzed_at": "2026-01-01T12:00:00Z",
            }
        )[:-1]
        + b',"report":'
        + raw.strip()
        + b"}"
    )


def ingest(call, project, body, expected=200):
    return decode(call("/analyses", body, project=project, expected=expected))


def read_inputs(paths):
    inputs, evidence = [], []
    for path in paths:
        raw = path.read_bytes()
        report = decode(raw)
        if not report["project"]["complete"] or not report.get("assessment"):
            raise ValueError(f"{path}: use a complete CLI report with --assessment")
        if report["assessment"]["context"].get("source_revision") is not None:
            raise ValueError(
                f"{path}: scan a pinned source archive without Git metadata"
            )
        issues = sum(len(f["issues"]) for f in report["files"])
        assert issues > 0 and len(raw) < CAP, path
        inputs.append((raw, issues))
        evidence.append(
            {
                "path": str(path),
                "bytes": len(raw),
                "sha256": sha(raw),
                "findings": issues,
                "files": len(report["files"]),
            }
        )
    return inputs, evidence


def finding_path(analysis):
    return f"/analyses/{analysis}/findings"


def findings(call, project, analysis):
    return decode(call(finding_path(analysis), project=project))["findings"]


def pages(call, project, analysis, limit=500):
    records, seen, cursor = [], set(), None
    while True:
        query = {"limit": limit}
        if cursor is not None:
            query["cursor"] = cursor
        result = decode(
            call(finding_path(analysis) + "/page?" + urlencode(query), project=project)
        )
        page, cursor = result["findings"], result["next_cursor"]
        assert len(page) <= limit
        records.extend(page)
        if cursor is None:
            return records, len(seen) + 1
        assert len(page) == limit and cursor not in seen
        seen.add(cursor)


def review(call, project, analysis, item, version, state, expected=200):
    return decode(
        call(
            "/reviews",
            encode(
                {
                    "schema_version": 1,
                    "analysis_id": analysis,
                    "kind": item["kind"],
                    "identity": item["identity"],
                    "state": state,
                    "reason": "qualification control",
                    "expected_version": version,
                }
            ),
            project=project,
            expected=expected,
        )
    )


def history(call, project, review_id):
    return decode(call(f"/reviews/{review_id}/history", project=project))["history"]


def sample_groups(results):
    return {
        name: {
            "calls": len(times),
            "p50_ms": sorted(times)[(len(times) - 1) // 2],
            "max_ms": max(times),
        }
        for name in sorted({name for name, _ in results})
        for times in [[duration for group, duration in results if group == name]]
    }


def concurrent(call, active, seeded, writes):
    tests = []
    for project, body in writes:

        def write(project=project, body=body):
            result = ingest(call, project, body)
            assert result["analysis"]["project"] == project
            return (
                result["analysis"]["commit"],
                result["analysis"]["id"],
                result["idempotent"],
            )

        tests.append(("write", write))
    for n in range(8 - len(tests)):
        project = active[n % len(active)]
        analysis = seeded[project]
        path = finding_path(analysis) + "/page?limit=100"
        expected = call(path, project=project)

        def read(project=project, path=path, expected=expected):
            assert (
                call(path, project=project, credential=project + "reader") == expected
            )

        tests.append(("page", read))
    barrier = Barrier(len(tests), timeout=10)

    def run(test):
        name, task = test
        barrier.wait()
        result, elapsed = timed(task)
        return name, elapsed, result

    with ThreadPoolExecutor(max_workers=len(tests)) as pool:
        result = list(pool.map(run, tests))
    return result


def workload(call, active, seed, reports):
    measurements, commits = [], {}
    for seq in range(ROUNDS):
        for_a = ingest_bytes(reports[seq][0], f"load-a-{seq}")
        writes = [("alpha", for_a), ("alpha", for_a)]
        if len(active) > 1:
            for_b = ingest_bytes(reports[seq + 1][0], f"load-b-{seq}")
            writes.extend([("beta", for_b), ("beta", for_b)])
        batch = concurrent(call, active, seed, writes)
        measurements.extend((name, elapsed) for name, elapsed, _ in batch)
        posted = [value for name, _, value in batch if name == "write"]
        for commit, analysis, _ in posted:
            replies = [(aid, idem) for label, aid, idem in posted if label == commit]
            assert sorted(replies) == [(analysis, False), (analysis, True)], replies
            commits[commit] = analysis
    return {"operations": sample_groups(measurements), "created_analyses": commits}


def seed_reviews(call, project, report, *, archive=None):
    raw, count = report
    source = ingest(call, project, ingest_bytes(raw, "original"))["analysis"]["id"]
    old = findings(call, project, source)
    assert len(old) == count
    item = next(f for f in old if not f["ambiguous"] and f["kind"] == "finding")
    before = review(call, project, source, item, 0, "accepted")
    barrier = Barrier(2, timeout=10)

    def race():
        body = encode(
            {
                "schema_version": 1,
                "analysis_id": source,
                "kind": item["kind"],
                "identity": item["identity"],
                "state": "resolved",
                "reason": "qualification control",
                "expected_version": 1,
            }
        )
        barrier.wait()
        status, raw = call("/reviews", body, project=project, expected=None)
        return status, decode(raw)["review"]["version"] if status == 200 else None

    with ThreadPoolExecutor(max_workers=2) as pool:
        replies = [pool.submit(race) for _ in range(2)]
        assert sorted(f.result() for f in replies) == [(200, 2), (409, None)]
    review_id = before["review"]["id"]
    chain = history(call, project, review_id)
    assert [entry["version"] for entry in chain] == [1, 2]
    if archive is not None:
        archive["payload"], archive["export_ms"] = timed(
            lambda: call("/export", project=project)
        )
        archive["original"] = relabel(call(finding_path(source), project=project))
    derived = ingest(call, project, ingest_bytes(raw, "unmodified"))["analysis"]["id"]
    for analysis in (source, derived):
        expected = findings(call, project, analysis)
        actual, _ = pages(call, project, analysis)
        assert actual == expected and len(actual) == count
        match = next(f for f in actual if f["identity"] == item["identity"])
        assert match["review"]["analysis_id"] == source
        assert (
            match["review"]["state"] == "resolved" and match["review"]["version"] == 2
        )
    return source, derived, review_id


def project_view(call, project, seed):
    source, derived, review_id = seed
    raw = call("/analyses", project=project)
    expected_ids = [row["id"] for row in decode(raw)["analyses"]]
    view = {
        "analyses": sha(raw),
        "gate_policy": sha(call("/gate-policy", project=project)),
    }
    for scope, branch in (("project", {}), ("branch", {"branch": "main"})):
        ids, cursors, query = [], set(), {"limit": 2, **branch}
        while True:
            doc = decode(call("/analyses/page?" + urlencode(query), project=project))
            ids.extend(row["id"] for row in doc["analyses"])
            cursor = doc["next_cursor"]
            if cursor is None:
                break
            assert cursor not in cursors
            cursors.add(cursor)
            query["cursor"] = cursor
        assert ids == expected_ids
        view[scope + "_history_pages"] = len(cursors) + 1
    for aid in (source, derived):
        full = call(finding_path(aid), project=project)
        actual, page_count = pages(call, project, aid)
        assert actual == decode(full)["findings"]
        view[str(aid)] = {
            "findings_sha256": sha(full),
            "findings": len(actual),
            "pages": page_count,
            "reviewed": sum("review" in f for f in actual),
        }
    view["review_history_sha256"] = sha(
        call(f"/reviews/{review_id}/history", project=project)
    )
    assert len(history(call, project, review_id)) == 2
    return view


def authorization_matrix(call, seeds):
    for p, other in (("alpha", "beta"), ("beta", "alpha")):
        own_projects = decode(call(project="", credential=p + "reader"))["projects"]
        assert [row["project"] for row in own_projects] == [p]
        pid = seeds[p][0]
        own = call(finding_path(pid) + "/page", project=p, credential=p + "reader")
        assert decode(own)["findings"]
        call(
            finding_path(pid) + "/page",
            project=p,
            credential=other + "reader",
            expected=403,
        )
        call(
            finding_path(seeds[other][0]) + "/page",
            project=p,
            credential=p + "reader",
            expected=404,
        )
        call("/analyses", b"{}", project=p, credential=p + "reader", expected=403)


def kill_after_commit(process, database, port, token, body, commit):
    # The client sends a complete request, then discards its response. Confirm
    # visibility before SIGKILL while an older read pins the WAL end mark.
    query = "SELECT id FROM analyses WHERE project='alpha' AND commit_sha=?"
    with (
        closing(sql_read(database)) as before,
        closing(HTTPConnection("127.0.0.1", port, timeout=20)) as connection,
    ):
        before.execute("BEGIN")
        assert before.execute(query, (commit,)).fetchone() is None
        connection.request(
            "POST",
            PREFIX + "/alpha/analyses",
            body,
            {
                "Authorization": "Bearer " + token,
                "Content-Type": "application/json",
            },
        )
        deadline = time.monotonic() + 10
        with closing(sql_read(database)) as db:
            while True:
                row = db.execute(query, (commit,)).fetchone()
                if row:
                    break
                assert time.monotonic() < deadline, "analysis was not committed"
                time.sleep(0.005)
        wal = Path(str(database) + "-wal").stat().st_size
        assert wal > 32 and before.execute(query, (commit,)).fetchone() is None
        _, elapsed = timed(lambda: (process.kill(), process.wait(timeout=5)))
    return row[0], {"wal_bytes_before_kill": wal, "kill_ms": elapsed}


def abandon_locked_write(process, database, port, token, body, commit):
    # This local test database deliberately holds the writer slot so the
    # submission cannot commit before SIGKILL. It simulates an interrupted
    # client submission without introducing a fault into the product.
    with (
        closing(sqlite3.connect(database)) as writer,
        closing(HTTPConnection("127.0.0.1", port, timeout=20)) as client,
    ):
        writer.execute("BEGIN IMMEDIATE")
        client.request(
            "POST",
            PREFIX + "/alpha/analyses",
            body,
            {
                "Authorization": "Bearer " + token,
                "Content-Type": "application/json",
            },
        )
        assert (
            writer.execute(
                "SELECT id FROM analyses WHERE commit_sha=?", (commit,)
            ).fetchone()
            is None
        )
        process.kill()
        process.wait(timeout=5)
        writer.rollback()


def backup(source, destination, progress=None):
    assert not destination.exists()
    with (
        closing(sql_read(source)) as db,
        closing(sqlite3.connect(destination)) as target,
    ):
        if progress is not None:
            # Keep one snapshot even if a writer commits between backup steps.
            db.execute("BEGIN")
            db.execute("SELECT count(*) FROM projects").fetchone()
        db.backup(target, pages=128, progress=progress)


def live_backup(call, source, destination, seeds, raw):
    ready, resume = Event(), Event()

    def pause_after_first_step(status, remaining, _total):
        if not ready.is_set() and status == sqlite3.SQLITE_OK and remaining:
            ready.set()
            assert resume.wait(35), "backup did not resume"

    read_checks = (
        ("alpha", finding_path(seeds["alpha"][0]) + "/page?limit=100"),
        ("beta", "/analyses/page?branch=main&limit=25"),
    )
    expected = {
        (project, path): call(path, project=project) for project, path in read_checks
    }
    barrier = Barrier(3, timeout=10)

    def read(project, path):
        barrier.wait()
        assert (
            call(path, project=project, credential=project + "reader")
            == expected[project, path]
        )

    def write():
        barrier.wait()
        late = ingest(call, "alpha", ingest_bytes(raw, "during-snapshot"))
        assert not late["idempotent"]
        return late["analysis"]["id"]

    with ThreadPoolExecutor(max_workers=4) as pool:
        copy = pool.submit(
            timed, lambda: backup(source, destination, pause_after_first_step)
        )
        try:
            assert ready.wait(10), "backup did not reach its first incremental step"
            readers = [
                pool.submit(timed, lambda p=p, q=q: read(p, q)) for p, q in read_checks
            ]
            writer = pool.submit(timed, write)
            results = [f.result()[1] for f in readers]
            late_id, write_ms = writer.result()
            assert (
                decode(call(f"/analyses/{late_id}/overview"))["analysis"]["commit"]
                == "during-snapshot"
            )
        finally:
            resume.set()
        _, elapsed = copy.result()
    return {
        "elapsed_with_paused_copy_ms": elapsed,
        "concurrent_reads_ms": dict(
            zip(("findings", "branch_history"), results, strict=True)
        ),
        "concurrent_ingest_ms": write_ms,
        "live_only_analysis_id": late_id,
    }


def integrity(database):
    with closing(sql_read(database)) as db:
        db.execute("BEGIN")
        assert db.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        assert not db.execute("PRAGMA foreign_key_check").fetchall()
        tables = (
            ("projects", db.execute("SELECT * FROM projects ORDER BY project")),
            ("analyses", db.execute("SELECT * FROM analyses ORDER BY id")),
            ("findings", db.execute("SELECT * FROM findings ORDER BY id")),
            ("reviews", db.execute("SELECT * FROM reviews ORDER BY id")),
            ("review_history", db.execute("SELECT * FROM review_history ORDER BY id")),
            ("deletion_audit", db.execute("SELECT * FROM deletion_audit ORDER BY id")),
            (
                "project_gate_policies",
                db.execute(
                    "SELECT * FROM project_gate_policies ORDER BY project, version"
                ),
            ),
        )
        counts = {}
        digest = hashlib.sha256()
        for table, rows in tables:
            digest.update(table.encode())
            count = 0
            for row in rows:
                digest.update(encode(row) + b"\n")
                count += 1
            counts[table] = count
        return {
            "schema_version": db.execute("PRAGMA user_version").fetchone()[0],
            "row_counts": counts,
            "rows_sha256": digest.hexdigest(),
        }


def assign_gate(call, expected_version, threshold):
    policy = decode(
        call(
            "/gate-policy",
            encode(
                {
                    "schema_version": 1,
                    "expected_version": expected_version,
                    "config": {
                        "schema_version": 1,
                        "conditions": [
                            {
                                "scope": "overall",
                                "metric": "files",
                                "operator": "lte",
                                "threshold": threshold,
                            }
                        ],
                    },
                }
            ),
            method="PUT",
        )
    )["policy"]
    assert policy["version"] == expected_version + 1


def observe_export_cap(call, report):
    last_bytes = None
    for n in range(12):
        status, raw = call("/export", expected=None)
        if status == 413:
            return {
                "added_before_refusal": n,
                "last_success_bytes": last_bytes,
                "refusal": status,
                "default_body_limit_bytes": CAP,
            }
        assert status == 200 and len(raw) <= CAP
        last_bytes = len(raw)
        result = ingest(call, "alpha", ingest_bytes(report, f"capacity-{n}"))
        assert not result["idempotent"]
    raise AssertionError("HTTP export limit was not reached after 12 bounded additions")


def relabel(raw):
    # Restore may remap storage IDs. Compare the semantic parts of findings
    # including the review payload and every immutable history entry.
    doc = decode(raw)
    for record in doc["findings"]:
        for key in ("id", "analysis_id"):
            if record.get("review"):
                record["review"].pop(key, None)
    return doc


def restore_http(binary, database, raw, original):
    archived = decode(raw)
    project = archived["project"]
    with service(binary, database) as (_, call, _, _, _):
        result, elapsed = timed(
            lambda: decode(call("/restore", raw, project=project))["restore"]
        )
        for key in ("analyses", "findings", "reviews", "history"):
            assert result[key] == len(archived[key]), (key, result)
        rows = decode(call("/analyses", project=project))["analyses"]
        ids = {row["commit"]: row["id"] for row in rows}
        assert relabel(call(finding_path(ids["original"]), project=project)) == original
        reexport = decode(call("/export", project=project))
        assert [a["report"] for a in reexport["analyses"]] == [
            a["report"] for a in archived["analyses"]
        ]
        (restore_review,) = reexport["reviews"]
        _, later = reexport["history"]
        assert (
            history(call, project, restore_review["id"])[-1]["version"]
            == later["version"]
            == 2
        )
        for restored, source in zip(
            reexport["history"], archived["history"], strict=True
        ):
            assert {
                k: v
                for k, v in restored.items()
                if k not in ("id", "analysis_id", "review_id")
            } == {
                k: v
                for k, v in source.items()
                if k not in ("id", "analysis_id", "review_id")
            }
    return {"archive_bytes": len(raw), "duration_ms": elapsed, "rows": result}


def qualify(binary, work, reports):
    single_db = work / "single.sqlite3"
    with service(binary, single_db) as (_, call, _, _, startup_ms):
        seed = seed_reviews(call, "alpha", reports[0])
        single = workload(call, ("alpha",), {"alpha": seed[0]}, reports)
        single.update(startup_ms=startup_ms, tables=integrity(single_db))

    multi = work / "multi.sqlite3"
    retry = ingest_bytes(reports[0][0], "lost-response")
    locked = ingest_bytes(reports[3][0], "interrupted")
    with service(binary, multi) as (process, call, port, tokens, _):
        archive = {}
        assign_gate(call, 0, 0)
        seeds = {
            "alpha": seed_reviews(call, "alpha", reports[0]),
            "beta": seed_reviews(call, "beta", reports[1], archive=archive),
        }
        assign_gate(call, 1, 10_000)
        authorization_matrix(call, seeds)
        after_two, _ = call("/export", project="beta", expected=None)
        assert after_two in (200, 413)
        archive["two_analysis_status"] = after_two
        mixed = workload(call, PROJECTS, {p: seeds[p][0] for p in PROJECTS}, reports)
        views_before_kill = {
            p: [sha(call(finding_path(aid), project=p)) for aid in seeds[p][:2]]
            for p in PROJECTS
        }
        accepted_id, committed = kill_after_commit(
            process, multi, port, tokens["alphaadmin"], retry, "lost-response"
        )

    with service(binary, multi) as (process, call, port, tokens, startup_ms):
        repeated, retry_ms = timed(lambda: ingest(call, "alpha", retry))
        assert repeated["idempotent"] and repeated["analysis"]["id"] == accepted_id
        ingest(
            call, "alpha", ingest_bytes(reports[1][0], "lost-response"), expected=409
        )
        restarted_views = {
            p: [sha(call(finding_path(aid), project=p)) for aid in seeds[p][:2]]
            for p in PROJECTS
        }
        assert restarted_views == views_before_kill
        committed.update(
            restart_ms=startup_ms,
            retry_ms=retry_ms,
            analysis_id=accepted_id,
            changed_body_status=409,
        )
        abandon_locked_write(
            process, multi, port, tokens["alphaadmin"], locked, "interrupted"
        )

    snapshot = work / "live-snapshot.sqlite3"
    recovered = work / "recovered.sqlite3"
    with service(binary, multi) as (_, call, _, _, startup_ms):
        recovered_write, fresh_ms = timed(lambda: ingest(call, "alpha", locked))
        assert not recovered_write["idempotent"]
        aborted_id = recovered_write["analysis"]["id"]
        assert ingest(call, "alpha", locked)["analysis"]["id"] == aborted_id
        interrupted = {
            "restart_ms": startup_ms,
            "retry_ms": fresh_ms,
            "created_analysis": aborted_id,
        }
        capacity = observe_export_cap(call, reports[0][0])
        removed = mixed["created_analyses"]["load-a-0"]
        call(
            f"/analyses/{removed}?reason=qualification",
            method="DELETE",
            expected=204,
        )
        views = {p: project_view(call, p, seed) for p, seed in seeds.items()}
        live_tables = integrity(multi)
        assert live_tables["row_counts"]["deletion_audit"] == 1
        assert live_tables["row_counts"]["project_gate_policies"] == 2
        overlap = live_backup(call, multi, snapshot, seeds, reports[2][0])
        assert integrity(snapshot) == live_tables

    _, recovery_copy_ms = timed(lambda: backup(snapshot, recovered))
    with service(binary, recovered) as (_, call, _, _, restart_ms):
        verify_start = time.monotonic()
        restored = {p: project_view(call, p, seed) for p, seed in seeds.items()}
        assert restored == views
        assert integrity(recovered) == live_tables
        assert ingest(call, "alpha", retry)["analysis"]["id"] == accepted_id
        for aid in (removed, overlap["live_only_analysis_id"]):
            call(f"/analyses/{aid}/overview", expected=404)
        assert decode(call("/gate-policy"))["policy"]["version"] == 2
        old = decode(call(f"/analyses/{seeds['alpha'][0]}/overview"))["analysis"]
        assert old["gate_policy_version"] == 1 and old["gate"]["status"] == "fail"
        new = decode(call(f"/analyses/{accepted_id}/overview"))["analysis"]
        assert new["gate_policy_version"] == 2 and new["gate"]["status"] == "pass"
        authorization_matrix(call, seeds)
        verify_ms = round((time.monotonic() - verify_start) * 1000, 3)

    http = restore_http(
        binary, work / "http-restore.sqlite3", archive["payload"], archive["original"]
    )
    http.update(
        export_ms=archive["export_ms"],
        two_analysis_status=archive["two_analysis_status"],
    )
    return {
        "single_tenant": single,
        "two_tenants": mixed,
        "committed_without_ack": committed,
        "interrupted_submission": interrupted,
        "export_limit": capacity,
        "http_backup": http,
        "sqlite_snapshot": {
            "online_backup": overlap,
            "restore_copy_ms": recovery_copy_ms,
            "restart_ms": restart_ms,
            "verify_ms": verify_ms,
            "backup_bytes": snapshot.stat().st_size,
            "tables": live_tables,
            "projects": views,
            "deleted_analysis_id": removed,
            "restored_policy_versions": [1, 2],
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    if not __debug__:
        parser.error(
            "run without Python optimization; assertions are qualification checks"
        )
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("reports", type=Path, nargs=4, metavar="REAL_REPORT")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    reports, evidence = read_inputs(args.reports)
    with tempfile.TemporaryDirectory(
        prefix="hoonarqube-service-qualification-"
    ) as name:
        results = qualify(binary, Path(name), reports)
    print(
        json.dumps(
            {
                "binary_sha256": sha(binary.read_bytes()),
                "host": f"{platform.system()} {platform.machine()}",
                "backup_sqlite_version": sqlite3.sqlite_version,
                "inputs": evidence,
                "workers": 4,
                "concurrent_clients": 8,
                "rounds": ROUNDS,
                **results,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
