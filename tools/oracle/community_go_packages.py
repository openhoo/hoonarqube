"""Replay Community Go gates and complete primary findings on 32 pinned public root packages."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
import tempfile

from community_scm_period import check
from project_gate_policy_replay import Client, cfg, ci, running_service
from public_corpus_summary import utf16_coordinates

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "tools/oracle/fixtures/community-go-packages/reference.json"
EXIT = {"pass": 0, "fail": 1, "unavailable": 2}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(db, *args):
    return subprocess.check_output(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "fetch.recurseSubmodules=false",
            "-C",
            db,
            *args,
        ],
        timeout=180,
    )


def object_store(case, mirrors, work):
    repository, commit = case["repository"], case["commit"]
    check(
        re.fullmatch(r"[\w.-]+/[\w.-]+", repository)
        and re.fullmatch(r"[0-9a-f]{40}", commit),
        "invalid repository or commit",
    )
    if mirrors:
        check(
            re.fullmatch(r"[\w.-]+/[\w.-]+", case["requested"]), "invalid mirror name"
        )
        return mirrors / case["requested"].replace("/", "--") / "objects"
    db = work / "objects"
    db.mkdir()
    git(db, "init", "--bare", "--quiet", "--template=")
    git(
        db,
        "fetch",
        "--quiet",
        "--depth=1",
        "--no-tags",
        "--no-recurse-submodules",
        "https://github.com/" + repository + ".git",
        commit,
    )
    return db


def stage_sources(case, mirrors, work):
    db = object_store(case, mirrors, work)
    check(
        git(db, "rev-parse", case["commit"] + "^{tree}").decode().strip()
        == case["tree"],
        "wrong public source tree",
    )
    root = work / "source"
    root.mkdir()
    files = {}
    for item in git(db, "ls-tree", "-z", case["commit"]).split(b"\0")[:-1]:
        metadata, pathname = item.split(b"\t", 1)
        name = pathname.decode()
        if not name.endswith(".go") or name.endswith("_test.go"):
            continue
        mode, kind, oid = metadata.split()
        check(
            re.fullmatch(r"[\w.-]+", name)
            and mode in (b"100644", b"100755")
            and kind == b"blob",
            f"unexpected source entry: {name}",
        )
        content = git(db, "cat-file", "blob", oid.decode())
        files[name] = digest(content)
        (root / name).write_bytes(content)
    check(files == case["files"], "complete root source inventory changed")
    return root


def measure(cli, root, files, *options):
    proc = subprocess.run(
        [
            cli,
            "analyze",
            *sorted(files),
            "--profile",
            "sonar-parity",
            "--format",
            "json",
            *options,
        ],
        cwd=root,
        timeout=240,
        capture_output=True,
    )
    report = json.loads(proc.stdout)
    check(
        report["project"]["complete"]
        and sorted(f["path"] for f in report["files"]) == sorted(files),
        "incomplete scanner report",
    )
    return proc.returncode, report


def findings(report, root, rules):
    active, inactive = Counter(), Counter()
    for file in report["files"]:
        path = file["path"]
        lines = (root / path).read_bytes().decode("utf-8").splitlines()
        for issue in file["issues"]:
            key = issue["rule_key"]
            if key in rules:
                active[
                    (key, path, *utf16_coordinates(issue, lines), issue["message"])
                ] += 1
            else:
                inactive[key] += 1
    return active, dict(inactive)


def assigned_gate(service, state, config, report, commit):
    # The service must apply its own versioned policy to the ordinary scanner report.
    token = secrets.token_urlsafe(32)
    roles = {key: token for key in ("admin", "scanner", "reader")}
    state.mkdir()
    with running_service(service, state, token) as port:
        client = Client(port, roles)
        assigned = client.assign("admin", 0, config)
        check(assigned["policy"]["version"] == 1, "wrong policy version")
        receipt = client.ingest(report, commit)
        analysis = receipt["analysis"]
        check(analysis["gate_policy_version"] == 1, "no assigned gate")
        gate = analysis["gate"]
        ci(receipt, EXIT[gate["status"]], commit=commit)
    with running_service(service, state, token) as port:
        persisted = Client(port, roles).call(
            "reader", f"/analyses/{analysis['id']}/gate"
        )
        check(persisted == gate, "stored gate changed across service restart")
    return gate


def ordered(counter):
    return sorted(
        counter.elements(),
        key=lambda row: tuple("" if x is None else str(x) for x in row),
    )


def compare(case, tier, rules, cli, service, root, raw, work):
    ref = case["references"][tier]
    check(
        sorted(case["files"]) == ref["indexed_go"],
        "reference did not index every input",
    )
    config = cfg("community_26_11_go_" + tier + "_violations", 0)
    policy = work / "policy.json"
    policy.write_text(json.dumps(config))
    code, report = measure(cli, root, case["files"], "--quality-gate", policy)
    gate = report["assessment"]["gate"]
    check(code == EXIT[gate["status"]], "CLI gate status and exit differed")
    stored = assigned_gate(
        service, work / ("store-" + tier), config, raw, case["commit"]
    )
    check(stored == gate, "assigned service gate differs from CLI gate")
    seen, inactive = findings(report, root, rules)
    expected = Counter(map(tuple, ref["active_issues"]))
    return {
        "repository": case["repository"],
        "commit": case["commit"],
        "analysis": ref["analysis"],
        "tier": tier,
        "files": len(case["files"]),
        "reference_gate": ref["reference_status"],
        "reference_violations": ref["reference_violations"],
        "cli_exit": code,
        "service_ci_exit": EXIT[stored["status"]],
        "native_violations": gate["conditions"][0]["actual"],
        "matching": ordered(seen & expected),
        "only_native": ordered(seen - expected),
        "only_reference": ordered(expected - seen),
        "native_inactive": inactive,
    }


def replay(case, tiers, profiles, cli, service, mirrors):
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        root = stage_sources(case, mirrors, work)
        code, raw = measure(cli, root, case["files"])
        check(
            code == 0 and not raw.get("assessment", {}).get("gate"),
            "invalid unassigned report",
        )
        return [
            compare(case, t, profiles[t], cli, service, root, raw, work) for t in tiers
        ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "binaries", type=Path, help="directory containing the candidate CLI and service"
    )
    parser.add_argument(
        "--mirrors", type=Path, help="optional offline OWNER--REPO/objects stores"
    )
    parser.add_argument(
        "--case", action="append", help="selected owner/repository; defaults to all 32"
    )
    parser.add_argument(
        "--output", type=Path, help="write complete issue multiset differences as JSON"
    )
    parser.add_argument("--tier", choices=("core", "extended", "both"), default="both")
    args = parser.parse_args()
    data = json.loads(REFERENCE.read_bytes())
    profiles = data["profiles"]
    catalog = json.loads(
        (ROOT / "catalog/reference/community-26.11-go-profiles.json").read_bytes()
    )
    check(
        catalog["server"] == data["server"]
        and all(
            rules == catalog["profiles"][tier]["rules"]
            for tier, rules in profiles.items()
        ),
        "reference profile rules or settings changed",
    )
    cases = {r["repository"]: r for r in data["cases"]}
    check(
        len(cases)
        == len({r["github_id"] for r in cases.values()})
        == len(data["cases"])
        == 32
        and sum(len(r["files"]) for r in cases.values()) == data["file_count"] == 324,
        "invalid frozen cohort",
    )
    tiers = ["core", "extended"] if args.tier == "both" else [args.tier]
    cli = args.binaries.resolve() / "hoonarqube"
    service = args.binaries.resolve() / "hoonarqube-service"
    rows = []
    for repo in args.case or cases:
        check(repo in cases, f"unknown repository: {repo}")
        rows.extend(replay(cases[repo], tiers, profiles, cli, service, args.mirrors))
    if args.output:
        args.output.write_text(
            json.dumps(
                {
                    "reference_sha256": digest(REFERENCE.read_bytes()),
                    "cli_sha256": digest(cli.read_bytes()),
                    "service_sha256": digest(service.read_bytes()),
                    "results": rows,
                },
                indent=2,
                ensure_ascii=False,
            )
            + "\n"
        )
    for r in rows:
        print(
            f"{r['repository']} {r['tier']}: reference {r['reference_gate']}, CLI/CI "
            f"{r['cli_exit']}/{r['service_ci_exit']}, exact/additional/missing "
            f"{len(r['matching'])}/{len(r['only_native'])}/{len(r['only_reference'])}"
        )
    mismatches = [
        (r["repository"], r["tier"])
        for r in rows
        if r["cli_exit"] != {"OK": 0, "ERROR": 1}[r["reference_gate"]]
    ]
    check(not mismatches, f"gate verdicts differ from Community: {mismatches}")


if __name__ == "__main__":
    main()
