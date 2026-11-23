#!/usr/bin/env python3
"""Verify combined coverage against Git and raw LCOV at three real Commander revisions."""

import argparse
import copy
import gzip
import hashlib
import json
import re
import secrets
import subprocess
import sys
import tempfile
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path

from commander_reference import REFERENCE, verify
from public_corpus_prepare import GIT_ENV
from public_coverage_gate_replay import RECEIPT, check

HERE = Path(__file__).resolve().parent
BASES = (
    "987f28966c71baecb0ef4a36780e727bcd575b31",
    "b51c0ea3d012ea165d7e50bb375f4db67b9d8e75",
)
SOURCES = ("index.js", "lib")
REV = "ba6d13ddb4243e5913367734f8c159089ffe7834"


def git(root, *args):
    return subprocess.check_output(
        ["git", "-c", "core.hooksPath=/dev/null", *args],
        cwd=root,
        env=GIT_ENV,
        timeout=120,
        text=True,
    )


def changed_lines(root, base):
    diff = git(
        root,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "-U0",
        base,
        REV,
        "--",
        *SOURCES,
    )
    result = {}
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            path = line[6:]
        elif line.startswith("@@ "):
            match = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", line)
            check(match, "invalid diff hunk")
            start, length = int(match[1]), int(match[2] or 1)
            if length:
                result.setdefault(path, set()).update(range(start, start + length))
    return result


def counts(raw, changed):
    # Use the raw LCOV observations, independently of HoonarQube's coverage importer.
    line_hits = line_total = branch_hits = branch_total = 0
    for record in raw.decode().splitlines():
        if record.startswith("SF:"):
            path = record[3:]
        elif record.startswith(("DA:", "BRDA:")):
            fields = record.split(":", 1)[1].split(",")
            if changed is not None and int(fields[0]) not in changed.get(path, ()):
                continue
            if record.startswith("DA:"):
                line_hits += int(fields[1]) > 0
                line_total += 1
            else:
                branch_hits += fields[3] != "-" and int(fields[3]) > 0
                branch_total += 1
    return (line_hits, line_total, branch_hits, branch_total)


def percent(numbers):
    ln, lines, bn, branches = numbers
    value = Decimal(100 * (ln + bn)) / Decimal(lines + branches)
    return float(value.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


def scan(cli, root, *options):
    proc = subprocess.run(
        [
            cli,
            "analyze",
            *SOURCES,
            "--format",
            "json",
            "--profile",
            "sonar-parity",
            *options,
        ],
        cwd=root,
        capture_output=True,
        check=False,
        timeout=120,
    )
    if not proc.stdout:
        raise ValueError(proc.stderr.decode(errors="replace")[:600])
    result = json.loads(proc.stdout)
    check(result["project"]["complete"], "public scan incomplete")
    return proc.returncode, result


def gate(scope, metric="coverage", threshold=80):
    result = {
        "metric": metric,
        "scope": scope,
        "threshold": threshold,
        "operator": "gte",
    }
    if metric == "coverage":
        result["precision"] = "one_decimal"
    return result


def reject_altered(request, port, token, route, stored):
    sample = next(iter(stored.values()))[0]
    for mutation in (
        "value",
        "line",
        "snapshot",
        "legacy",
        "exception",
        "denominator",
    ):
        src = (
            stored["policy-987f2896"][0]
            if mutation in ("exception", "denominator")
            else sample
        )
        bad = copy.deepcopy(src)
        bad["branch"] = "invalid-" + mutation
        assessment = bad["report"]["assessment"]
        if mutation in ("exception", "denominator"):
            condition = assessment["gate"]["conditions"][0]
            if mutation == "exception":
                del condition["small_change_policy"]
            else:
                condition["ignored_on_small_change"] = 4
        elif mutation == "value":
            assessment["gate"]["conditions"][1]["actual"] += 0.1
        elif mutation == "legacy":
            del assessment["new_code"]["changed_source_lines"]
        else:
            row = assessment["new_code"]["changed_source_lines"][0]
            if mutation == "line":
                row["lines"].append(9999999)
            else:
                row["path"] = "nonexistent.js"
        try:
            request(port, token, route, bad)
        except RuntimeError as exc:
            check(
                "HTTP 400:" in str(exc) or "HTTP 409:" in str(exc),
                "wrong rejection",
            )
        else:
            raise ValueError("service accepted " + mutation)


def assigned_coverage(request, port, token, stored):
    condition = {**gate("new_code", threshold=95), "small_change_policy": "community20"}
    config = {"schema_version": 1, "conditions": [condition]}
    assignment = request(
        port,
        token,
        "/smoke/gate-policy",
        {"schema_version": 1, "expected_version": 0, "config": config},
        method="PUT",
    )
    check(
        assignment["policy"]["version"] == 1
        and assignment["policy"]["config"] == config,
        "assigned coverage configuration changed",
    )
    results = {}
    for name, previous in (
        ("small", "policy-987f2896"),
        ("large", "policy-b51c0ea3"),
        ("empty", "unchanged"),
        ("missing", "missing-policy-coverage"),
    ):
        body = copy.deepcopy(stored[previous][0])
        body["branch"] = "assigned-" + name
        expected = body["report"]["assessment"].pop("gate")
        response = request(port, token, "/smoke/analyses", body)["analysis"]
        check(
            response["gate_policy_version"] == 1 and response["gate"] == expected,
            "server-assigned coverage policy disagrees with CLI",
        )
        stored[body["branch"]] = (body, response["id"])
        results[name] = expected["status"]
    return results


def verify_service(service, work, cases):
    sys.path.insert(0, str(HERE.parents[1] / "scripts"))
    from smoke_cli_service import request, running_service

    token = secrets.token_urlsafe(32)
    route = "/smoke/analyses"
    stored = {}
    with running_service(service, work, token) as port:
        for name, report in cases.items():
            body = {
                "schema_version": 1,
                "branch": name,
                "commit": REV,
                "analyzed_at": "2026-11-22T00:00:00Z",
                "report": report,
            }
            answer = request(port, token, route, body)
            check(not answer["idempotent"], "unexpected first retry")
            stored[name] = (body, answer["analysis"]["id"])
        reject_altered(request, port, token, route, stored)
        assigned = assigned_coverage(request, port, token, stored)
    with running_service(service, work, token) as port:
        for body, analysis_id in stored.values():
            detail = request(port, token, f"{route}/{analysis_id}")["analysis"]
            retry = request(port, token, route, body)
            check(
                detail["report"] == body["report"]
                and retry["idempotent"]
                and retry["analysis"]["id"] == analysis_id,
                "restart/retry mismatch",
            )
    return {"persisted_and_retried": len(stored), "rejected": 6, "assigned": assigned}


def prepare_baselines(cli, work, repository):
    root = work / "source"
    root.mkdir()
    git(root, "init", "-q")
    git(
        root,
        "fetch",
        "-q",
        "--no-tags",
        "--depth=1",
        "--update-shallow",
        repository,
        *BASES,
        REV,
    )
    basepaths = {}
    for base in BASES:
        git(root, "checkout", "-q", "--detach", base)
        rc, report = scan(cli, root, "--assessment")
        check(
            rc == 0 and report["assessment"]["context"]["source_revision"] == base,
            "bad baseline",
        )
        path = work / (base + ".json")
        path.write_text(json.dumps(report))
        basepaths[base] = path
    git(root, "checkout", "-q", "--detach", REV)
    receipt = json.loads(RECEIPT.read_bytes())
    check(
        git(root, "rev-parse", "HEAD^{tree}").strip() == receipt["source"]["tree"],
        "wrong tree",
    )
    check(
        all(
            hashlib.sha256((root / k).read_bytes()).hexdigest() == v
            for k, v in receipt["source_sha256"].items()
        ),
        "incorrect Commander source",
    )
    return root, basepaths, receipt


def coverage_cases(root, basepaths, receipt, reference, reference_ids, run_gate, cases):
    summary = []
    (root / ".hoonarqube-replay").mkdir()
    for suite in ("focused", "broad"):
        raw = gzip.decompress(
            (HERE / "fixtures" / "commander-lcov" / f"{suite}.lcov.gz").read_bytes()
        )
        check(
            hashlib.sha256(raw).hexdigest() == receipt["cases"][suite]["lcov_sha256"],
            "wrong LCOV",
        )
        # CI can store test artifacts beside the checkout. Send an external
        # report through the same ingestion and restart checks as the local one.
        lcov = (
            root.parent / "broad.lcov"
            if suite == "broad"
            else Path(".hoonarqube-replay/focused.lcov")
        )
        (root / lcov).write_bytes(raw)
        for base, expected_lines in zip(BASES, (5, 48), strict=True):
            changed = changed_lines(root, base)
            check(
                sum(map(len, changed.values())) == expected_lines, "unexpected Git diff"
            )
            overall, scoped = counts(raw, None), counts(raw, changed)
            expected = [percent(overall), percent(scoped)]
            rc, report = run_gate(
                [gate("overall"), gate("new_code")],
                "--baseline",
                basepaths[base],
                "--coverage-lcov",
                lcov,
            )
            a = report["assessment"]
            new = a["new_code"]
            check(
                {r["path"]: set(r["lines"]) for r in new["changed_source_lines"]}
                == changed,
                "reported change set differs from Git",
            )
            actual = [item["actual"] for item in a["gate"]["conditions"]]
            check(
                actual == expected and rc == int(min(expected) < 80),
                f"{suite}/{base[:8]}: {actual=} {expected=} {rc=} {a['gate']}",
            )
            name = suite + "-" + base[:8]
            reference_ids[name] = verify(
                reference["cases"][name],
                suite,
                base,
                REV,
                hashlib.sha256(raw).hexdigest(),
                overall,
                scoped,
                expected_lines,
                a["gate"],
                rc,
                False,
            )
            cases[name] = report
            summary.append(
                {
                    "case": name,
                    "changed_lines": expected_lines,
                    "overall": overall,
                    "new_code": scoped,
                    "percent": actual,
                    "cli_exit": rc,
                    "finding_comparison": new["status"],
                }
            )
    return summary


def replay(cli, service, work, repository):
    root, basepaths, receipt = prepare_baselines(cli, work, repository)
    reference = json.loads(REFERENCE.read_bytes())
    reference_ids = {}
    config = work / "gate.json"

    def run_gate(conditions, *args):
        config.write_text(json.dumps({"schema_version": 1, "conditions": conditions}))
        return scan(cli, root, "--quality-gate", config, *args)

    cases = {}
    summary = coverage_cases(
        root, basepaths, receipt, reference, reference_ids, run_gate, cases
    )
    policy = {**gate("new_code", threshold=95), "small_change_policy": "community20"}
    exception_results = []
    focused = Path(".hoonarqube-replay/focused.lcov")
    for base, measured, ignored, want in [
        (BASES[0], 80.0, 5, 0),
        (BASES[1], 94.4, None, 1),
    ]:
        rc, report = run_gate(
            [policy], "--baseline", basepaths[base], "--coverage-lcov", focused
        )
        decision = report["assessment"]["gate"]["conditions"][0]
        check(
            rc == want
            and decision["actual"] == measured
            and decision.get("ignored_on_small_change") == ignored,
            "wrong small-change decision",
        )
        name = "policy-" + base[:8]
        raw = (root / focused).read_bytes()
        changed = changed_lines(root, base)
        reference_ids[name] = verify(
            reference["cases"][name],
            "focused",
            base,
            REV,
            hashlib.sha256(raw).hexdigest(),
            counts(raw, None),
            counts(raw, changed),
            sum(map(len, changed.values())),
            report["assessment"]["gate"],
            rc,
            True,
        )
        cases[name] = report
        exception_results.append(
            {"base": base, "actual": measured, "ignored_count": ignored, "exit": rc}
        )
    rc, candidate = scan(cli, root, "--assessment")
    check(rc == 0, "failed to capture unchanged candidate")
    self_base = work / "self.json"
    self_base.write_text(json.dumps(candidate))
    rc, report = run_gate([policy], "--baseline", self_base, "--coverage-lcov", focused)
    decision = report["assessment"]["gate"]["conditions"][0]
    check(
        rc == 0
        and decision["status"] == "no_value"
        and decision["actual"] is None
        and "ignored_on_small_change" not in decision,
        "empty scope must not synthesize a measurement",
    )
    cases["unchanged"] = report
    for name, conds, opts in [
        ("missing-policy-coverage", [policy], ["--baseline", self_base]),
        ("without-coverage", [gate("new_code")], ["--baseline", basepaths[BASES[0]]]),
        ("without-baseline", [gate("new_code")], ["--coverage-lcov", focused]),
        (
            "uncertain-findings",
            [gate("new_code"), gate("new_code", "issues", 0)],
            ["--coverage-lcov", focused, "--baseline", basepaths[BASES[0]]],
        ),
    ]:
        rc, report = run_gate(conds, *opts)
        check(rc == 2 and report["assessment"]["gate"]["status"] == "unavailable", name)
        cases[name] = report
    return {
        "repository": "tj/commander.js",
        "revision": REV,
        "baselines": BASES,
        "reference": "Git diff, raw LCOV and captured project gates on SonarQube Community Build "
        + reference["server_version"],
        "reference_analysis_ids": reference_ids,
        "cases": summary,
        "policy_cases": exception_results,
        "negative_cases": [
            "missing-policy-coverage",
            "without-coverage",
            "without-baseline",
            "uncertain-findings",
        ],
        "http": verify_service(service, work, cases),
    }


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary_directory", type=Path)
    p.add_argument("--repository", default="https://github.com/tj/commander.js.git")
    args = p.parse_args()
    binaries = args.binary_directory.resolve()
    with tempfile.TemporaryDirectory() as tmp:
        print(
            json.dumps(
                replay(
                    binaries / "hoonarqube",
                    binaries / "hoonarqube-service",
                    Path(tmp),
                    args.repository,
                ),
                indent=2,
            )
        )
