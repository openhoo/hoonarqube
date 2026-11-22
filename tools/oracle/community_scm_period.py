#!/usr/bin/env python3
"""Verify the SCM CLI against captured Community conditions, using full local Git histories."""

import argparse
import gzip
import hashlib
import json
import math
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

from community_combined_coverage import SOURCES, changed_lines, gate
from community_new_duplication import CONFIG, duplicate_lines, prepare
from public_corpus_prepare import GIT_ENV

HERE = Path(__file__).resolve().parent


def read(name):
    return json.loads((HERE / name).read_bytes())


def check(result, message):
    if not result:
        raise ValueError(message)


def git(root, *args):
    subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", *args],
        cwd=root,
        env=GIT_ENV,
        check=True,
        timeout=180,
    )


def scan(cli, root, paths, *args):
    result = subprocess.run(
        [cli, "analyze", *paths, "--profile", "sonar-parity", "--json", *args],
        capture_output=True,
        cwd=root,
        timeout=240,
    )
    check(result.stdout, f"no report: {result.stderr[:500]!r}")
    report = json.loads(result.stdout)
    check(report["project"]["complete"], "incomplete source inventory")
    return result.returncode, report


def descriptor(period, analysis_id, revision):
    check(
        period["mode"] == "SPECIFIC_ANALYSIS" and period["parameter"] == analysis_id,
        "wrong selected analysis",
    )
    return {
        "analysis_id": analysis_id,
        "revision": revision,
        "timestamp_ms": int(datetime.fromisoformat(period["date"]).timestamp()) * 1000,
    }


def write(path, value):
    path.write_text(json.dumps(value))


def run_case(cli, root, work, paths, base, head, selection, conditions, *extra):
    git(root, "checkout", "-q", "--detach", base)
    baseline = work / "baseline.json"
    code, before = scan(cli, root, paths, "--write-baseline", baseline)
    check(
        code == 0 and before["assessment"]["context"]["source_revision"] == base,
        "baseline mismatch",
    )
    git(root, "checkout", "-q", "--detach", head)
    selected = work / "period.json"
    write(selected, selection)
    config = work / "gate.json"
    write(config, {"schema_version": 1, "conditions": conditions})
    opts = [
        "--baseline",
        baseline,
        "--specific-analysis",
        selected,
        "--quality-gate",
        config,
        *extra,
    ]
    code, report = scan(cli, root, paths, *opts)
    new = report["assessment"]["new_code"]
    check(
        report["assessment"]["context"]["source_revision"] == head
        and new.get("specific_analysis") == selection
        and new.get("changed_source_lines") == new["lines"],
        f"unverified SCM inventory: {new['diagnostics']}",
    )
    return code, report, opts


def redux(cli, root, work):
    ref = read("community-hotspot-reference-redux.json")
    base, head = ref["revisions"]
    paths = [ref["source"]]
    period = descriptor(ref["candidate_gate"]["period"], ref["analysis_ids"][0], base)
    conditions = [
        {
            "scope": "new_code",
            "metric": "community_26_9_violations",
            "operator": "lte",
            "threshold": 0,
        },
        {
            "scope": "new_code",
            "metric": "community_26_9_security_hotspots_reviewed",
            "operator": "gte",
            "threshold": 100,
        },
    ]
    rc, report, opts = run_case(cli, root, work, paths, base, head, period, conditions)
    a = report["assessment"]
    values = [c["actual"] for c in a["gate"]["conditions"]]
    check(
        rc == 0
        and values == [0, None]
        and a["new_code"]["lines"] == []
        and ref["candidate_gate"]["conditions"][0]["actualValue"] == "0",
        "Redux reference mismatch",
    )
    legacy, before = scan(cli, root, paths, *opts[:2], *opts[4:])
    check(
        legacy == 1 and before["assessment"]["gate"]["conditions"][0]["actual"] == 2,
        "legacy diff changed",
    )

    def unavailable(args, why):
        code, data = scan(cli, root, paths, *args)
        new = data["assessment"]["new_code"]
        check(
            code == 2
            and data["assessment"]["gate"]["status"] == "unavailable"
            and new.get("changed_source_lines") is None,
            f"{why} became a decision",
        )
        return why

    controls = [unavailable(opts[2:], "missing baseline")]
    write(opts[3], {**period, "revision": head})
    controls.append(unavailable(opts, "wrong baseline revision"))
    write(opts[3], period)
    path = root / paths[0]
    raw = path.read_bytes()
    check(
        hashlib.sha256(raw).hexdigest() == ref["public_source_sha256"][head],
        "Redux source mismatch",
    )
    path.write_bytes(raw + b"\n")
    controls.append(unavailable(opts, "dirty source"))
    path.write_bytes(raw)
    (root / ".git" / "shallow").write_text(base + "\n")
    controls.append(unavailable(opts, "shallow history"))
    return {
        "reference_analysis": ref["analysis_ids"][1],
        "specific_analysis": rc,
        "legacy": legacy,
        "new_violations": values[0],
        "reviewed_percent": values[1],
        "unavailable": controls,
    }


def duplication(cli, roots, work):
    periods = read("community-scm-duplication-periods.json")
    result = []
    for case in read("community-new-duplication-20261122.json")["cases"]:
        base, head, path = case["base"], case["candidate"], case["path"]
        root = roots[case["repo"]]
        for pin in (base, head):
            prepare(root, path, pin)
        selected = descriptor(
            periods[case["project"]]["period"], base["analysisId"], base["revision"]
        )
        code, report, _ = run_case(
            cli,
            root,
            work,
            [path],
            base["revision"],
            head["revision"],
            selected,
            [CONFIG],
        )
        ref = case["reference"]
        lines = {
            n for e in report["assessment"]["new_code"]["lines"] for n in e["lines"]
        }
        dup = len(duplicate_lines(report, path) & lines)
        cond = report["assessment"]["gate"]["conditions"][0]
        expected_dup = case["native"]["duplicated"]
        if expected_dup is None:
            expected_dup = ref["duplicated"]
        check(
            len(lines) == ref["new"]
            and dup == expected_dup
            and code == int(ref["status"] == "ERROR")
            and bool(cond.get("ignored_on_small_change")) == ref["ignored"]
            and math.isclose(cond["actual"], 100 * dup / len(lines)),
            f"duplication mismatch: {case['project']}",
        )
        result.append(
            {
                "project": case["project"],
                "analysis": head["analysisId"],
                "new": len(lines),
                "native_duplicated": dup,
                "reference_duplicated": ref["duplicated"],
                "exit": code,
            }
        )
    return result


def commander(cli, root, work):
    result = []
    for name, case in read("community-commander-sonar-26.9.json")["cases"].items():
        if name.startswith("policy"):
            continue
        suite = name.split("-")[0]
        raw = gzip.decompress(
            (HERE / "fixtures" / "commander-lcov" / f"{suite}.lcov.gz").read_bytes()
        )
        check(hashlib.sha256(raw).hexdigest() == case["lcov_sha256"], "wrong LCOV")
        lcov = work / "coverage.lcov"
        lcov.write_bytes(raw)
        base, head, ref = case["baseline"], case["candidate"], case["decision"]
        selected = descriptor(ref["period"], base["analysisId"], base["revision"])
        code, report, _ = run_case(
            cli,
            root,
            work,
            SOURCES,
            base["revision"],
            head["revision"],
            selected,
            [gate("overall"), gate("new_code")],
            "--coverage-lcov",
            lcov,
        )
        new = report["assessment"]["new_code"]["lines"]
        expected_lines = changed_lines(root, base["revision"])
        for path, extra in case["scm_only"].items():
            expected_lines.setdefault(path, set()).update(extra)
        check(
            {f["path"]: set(f["lines"]) for f in new} == expected_lines,
            "SCM membership differs from captured /api/sources/lines",
        )
        measured = sum(len(x["lines"]) for x in new)
        vals = [c["actual"] for c in report["assessment"]["gate"]["conditions"]]
        check(
            measured == int(case["measures"]["new_lines"])
            and vals
            == [float(case["measures"][k]) for k in ("coverage", "new_coverage")]
            and code == int(ref["status"] == "ERROR"),
            f"Commander mismatch: {name} {measured=} {vals=}",
        )
        result.append(
            {
                "case": name,
                "analysis": head["analysisId"],
                "new_lines": measured,
                "coverage": vals,
                "exit": code,
            }
        )
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("scanner", type=Path)
    for name in ("redux", "fastapi", "yjs", "commander"):
        p.add_argument(
            "--" + name,
            type=Path,
            required=True,
            help="full clone containing the captured revisions",
        )
    args = p.parse_args()
    cli = args.scanner.resolve(strict=True)
    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp).resolve()
        roots = {}
        for name in ("redux", "fastapi", "yjs", "commander"):
            roots[name] = work / name
            git(
                work,
                "clone",
                "--quiet",
                "--shared",
                "--no-checkout",
                "--",
                str(getattr(args, name).resolve(strict=True)),
                str(roots[name]),
            )
        result = {
            "redux": redux(cli, roots["redux"], work),
            "duplication": duplication(cli, roots, work),
            "commander": commander(cli, roots["commander"], work),
        }
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
