"""Replay the measured 26.11 Go profiles with the shipped CLI, cache and service."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile

from community_scm_period import check
from project_gate_policy_replay import Client, cfg, ci, running_service

ROOT = Path(__file__).resolve().parents[2]
FIX = ROOT / "tools/oracle/fixtures/community-go-26.11"
EVIDENCE = json.loads((FIX / "evidence.json").read_bytes())
PROFILES = json.loads(
    (ROOT / "catalog/reference/community-26.11-go-profiles.json").read_bytes()
)["profiles"]


def metric(tier):
    return "community_26_11_go_" + tier + "_violations"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def scan(binary, cwd, paths, *options):
    process = subprocess.run(
        [binary, "analyze", *paths, "--json", *options],
        cwd=cwd,
        capture_output=True,
        timeout=120,
    )
    check(bool(process.stdout), f"CLI returned no report: {process.stderr[:300]!r}")
    return process.returncode, json.loads(process.stdout)


def result(gate, tier, actual):
    (cond,) = gate["conditions"]
    status = "unavailable" if actual is None else ("fail" if actual else "pass")
    check(
        gate["status"] == cond["status"] == status
        and cond["actual"] == actual
        and cond["metric"] == metric(tier),
        f"unexpected {tier} gate: {cond}",
    )
    return cond.get("diagnostic", "")


def native_findings(files, active):
    return sorted(
        (
            i["rule_key"],
            i["range"]["start"]["line"],
            i["range"]["start"]["column"],
            i["range"]["end"]["line"],
            i["range"]["end"]["column"],
            i["message"],
        )
        for f in files
        for i in f["issues"]
        if i["rule_key"] in active
    )


def reference_findings(rows):
    return sorted(
        (
            i["rule"],
            i["line"],
            i["textRange"]["startOffset"],
            i["textRange"]["endLine"],
            i["textRange"]["endOffset"],
            i["message"],
        )
        for i in rows
    )


def cache_state(root):
    return {
        str(p.relative_to(root)): (digest(p.read_bytes()), p.stat().st_mtime_ns)
        for p in root.rglob("*")
        if p.is_file()
    }


def source_case(cli, work, name, src, ref):
    cache = work / (name + "-cache")
    gate = work / "gate.json"
    previous = {}
    seen = set()
    for tier in ("core", "extended", "comprehensive", "core"):
        gate.write_text(json.dumps(cfg(metric(tier), 0)))
        code, report = scan(
            cli, src.parent, [src.name], "--quality-gate", gate, "--cache-dir", cache
        )
        rows = ref[tier]["findings"]
        wanted = None if tier == "comprehensive" else len(rows)
        check(
            code == (2 if wanted is None else int(wanted > 0)), f"wrong {tier} CLI exit"
        )
        diag = result(report["assessment"]["gate"], tier, wanted)
        if wanted is None:
            check("go:S978: absent" in diag, "comprehensive silently dropped S978")
        else:
            check(
                native_findings(report["files"], PROFILES[tier]["rules"])
                == reference_findings(rows),
                f"{name} differs from live {tier} source locations or messages",
            )
        state = cache_state(cache)
        check(
            previous.items() <= state.items()
            and len(state) == len(previous) + int(tier not in seen),
            "gate configuration failed to isolate cache entries or reuse the original entry",
        )
        seen.add(tier)
        previous = state
    code, raw = scan(cli, src.parent, [src.name])
    check(
        code == 0 and "gate" not in raw.get("assessment", {}),
        "ordinary native scan produced gate",
    )
    return raw


def prepare_public(work, repo):
    cap = EVIDENCE["public"]
    rev = cap["revision"]
    checkout = work / "public-git"
    if repo is None:
        checkout.mkdir()
        subprocess.run(["git", "init", "-q", checkout], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                checkout,
                "fetch",
                "-q",
                "--no-tags",
                "--depth=1",
                "https://github.com/tidwall/match.git",
                rev,
            ],
            check=True,
            timeout=120,
        )
    else:
        checkout = repo

    def obj(*args):
        return subprocess.check_output(["git", "-C", checkout, *args], timeout=45)

    check(
        obj("rev-parse", rev + "^{tree}").decode().strip() == cap["tree"],
        "wrong upstream tree",
    )
    ((name, pin),) = cap["sources"].items()
    data = obj("show", rev + ":" + name)
    check(
        obj("rev-parse", rev + ":" + name).decode().strip() == pin["git_blob"]
        and digest(data) == pin["sha256"],
        "upstream source differs",
    )
    stage = work / "public"
    stage.mkdir()
    path = stage / name
    path.write_bytes(data)
    return path


def controls(cli, work):
    stage = work / "controls"
    stage.mkdir()
    sources = ROOT / ".oracle/sonar/projects/oracle-go/src"
    keys = list(PROFILES["extended"]["rules"])
    for key in keys:
        for variant in ("bad", "good"):
            name = key.split(":")[1].lower() + "_" + variant + ".go"
            shutil.copyfile(sources / name, stage / name)
    code, report = scan(cli, stage, [p.name for p in sorted(stage.iterdir())])
    check(code == 0 and report["project"]["complete"], "incomplete Go controls")
    by_name = {f["path"]: {i["rule_key"] for i in f["issues"]} for f in report["files"]}
    for key in keys:
        prefix = key.split(":")[1].lower()
        check(
            key in by_name[prefix + "_bad.go"]
            and key not in by_name[prefix + "_good.go"],
            "detector control failed: " + key,
        )
    gate = work / "gate.json"
    gate.write_text(json.dumps(cfg(metric("extended"), 0)))
    # Main-only S1192 drops out on an explicitly classified test; S3776 still applies.
    shutil.copyfile(FIX / "boundary.go", stage / "declared.go")
    code, r = scan(
        cli,
        stage,
        ["declared.go"],
        "--test-include",
        "declared.go",
        "--quality-gate",
        gate,
    )
    check(
        code == 1 and r["project"]["files"][0]["classification"] == "test",
        "test classification missing",
    )
    result(r["assessment"]["gate"], "extended", 1)
    code, r = scan(cli, stage, ["."], "--quality-gate", gate)
    check(
        code == 2 and "explicit" in result(r["assessment"]["gate"], "extended", None),
        "directory scan silently narrowed the selected sources",
    )
    (stage / "extra.js").write_text("export const x = 1;\n")
    code, r = scan(cli, stage, ["declared.go", "extra.js"], "--quality-gate", gate)
    check(
        code == 2 and "Go-only" in result(r["assessment"]["gate"], "extended", None),
        "mixed scope became qualified",
    )
    (stage / "broken.go").write_text("package fail\nfunc run( {\n")
    code, r = scan(cli, stage, ["broken.go"], "--quality-gate", gate)
    check(
        code == 2 and "incomplete" in result(r["assessment"]["gate"], "extended", None),
        "syntax failure became zero",
    )

    reference = work / "generic.json"
    reference.write_text('{"rules": [], "issues": []}')
    baseline = work / "reference-baseline.json"
    code, r = scan(
        cli,
        stage,
        ["declared.go"],
        "--quality-gate",
        gate,
        "--parity-reference",
        reference,
        "--write-baseline",
        baseline,
    )
    check(
        code == 2 and r["parity"]["completeness"] == "incomplete",
        "divergent reference did not block the scan",
    )
    result(r["assessment"]["gate"], "extended", None)
    check(baseline.is_file(), "scanner did not save the finalized baseline")
    saved = json.loads(baseline.read_bytes())
    check(
        saved["parity"] == r["parity"]
        and saved["assessment"]["gate"] == r["assessment"]["gate"],
        "baseline preserved an earlier gate verdict",
    )


def stored(service, work, report):
    tokens = {
        role: secrets.token_urlsafe(32) for role in ("admin", "reader", "scanner")
    }
    creds = [
        {"user_id": r, "token": tokens[r], "projects": {"smoke": r}}
        for r in ("reader", "scanner")
    ]

    def start():
        return running_service(service, work, tokens["admin"], extra_credentials=creds)

    rev = EVIDENCE["public"]["revision"]
    receipts = []
    with start() as port:
        client = Client(port, tokens)
        for version, (tier, count) in enumerate(
            (("core", 0), ("extended", 3), ("comprehensive", None)), 1
        ):
            client.assign("admin", version - 1, cfg(metric(tier), 0))
            resp = client.ingest(report, rev, tier)
            code = {0: 0, 3: 1, None: 2}[count]
            ci(resp, code, commit=rev)
            row = resp["analysis"]
            check(
                row["gate_policy_version"] == version
                and row["branch"] == tier
                and row["commit"] == rev,
                "receipt did not bind policy or source",
            )
            result(row["gate"], tier, count)
            receipts.append((row["id"], row["gate"], version))
        client.assign("admin", 3, cfg(metric("extended"), 0))
        for label in ("old", "threshold", "scope", "missing", "catalog", "inventory"):
            altered = copy.deepcopy(report)
            parity = altered["parity"]
            evidence = parity["go_gate_evidence"]
            if label == "old":
                del parity["go_gate_evidence"]
            elif label == "threshold":
                evidence["detectors"]["go:S1192"]["parameters"]["threshold"] = "4"
            elif label == "scope":
                evidence["detectors"]["go:S1763"]["main_only"] = False
            elif label == "missing":
                del evidence["detectors"]["go:S1656"]
            elif label == "catalog":
                evidence["catalog_sha256"] = "0" * 64
            else:
                parity["active_rules"].pop()
            resp = client.ingest(altered, rev, label)
            ci(resp, 2, commit=rev)
            result(resp["analysis"]["gate"], "extended", None)
    with start() as port:
        client = Client(port, tokens)
        for rid, gate, version in receipts:
            row = client.call("reader", f"/analyses/{rid}")["analysis"]
            check(
                row["gate_policy_version"] == version and client.current(rid) == gate,
                "stored profile result changed after reassignment/restart",
            )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("bin_dir", type=Path)
    p.add_argument("--public-repo", type=Path)
    args = p.parse_args()
    binary = args.bin_dir.resolve()
    cli = binary / "hoonarqube"
    with tempfile.TemporaryDirectory() as temp:
        # The scanner deliberately refuses symlinks in baseline destinations.
        work = Path(temp).resolve()
        source = FIX / "boundary.go"
        pinned = {v["source_sha256"] for v in EVIDENCE["boundary"].values()}
        check(pinned == {digest(source.read_bytes())}, "boundary source changed")
        source_case(cli, work, "boundary", source, EVIDENCE["boundary"])
        upstream = prepare_public(work, args.public_repo)
        raw = source_case(cli, work, "public", upstream, EVIDENCE["public"]["profiles"])
        controls(cli, work)
        stored(binary / "hoonarqube-service", work, raw)
    print(
        "Community Go profiles: boundaries, nine detector pairs, public locations, cache reuse and persisted CI decisions verified."
    )


if __name__ == "__main__":
    main()
