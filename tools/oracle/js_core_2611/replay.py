"""Replay the public JS inputs, using immutable source bytes and both Commander histories."""

import argparse
from collections import Counter
import gzip
import json
from pathlib import Path
import subprocess
import tempfile

from freeze import by_quality, digest, keyed, need, read

HERE = Path(__file__).resolve().parent
NAME = "community-26.11-javascript-core"
REFERENCE = read(HERE / "reference.json")


def git(root, *args):
    return subprocess.check_output(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "fetch.recurseSubmodules=false",
            "-C",
            root,
            *args,
        ],
        timeout=180,
    )


def restore(root, row, repository, mirrors):
    rev = row["revision"]
    if not (root / ".git").exists():
        git(root, "init", "-q")
    remote = (
        mirrors[repository]
        if mirrors is not None
        else "https://github.com/" + repository + ".git"
    )
    if subprocess.run(
        ["git", "-C", root, "cat-file", "-e", rev + "^{commit}"], capture_output=True
    ).returncode:
        git(root, "fetch", "-q", "--no-tags", "--update-shallow", remote, rev)
    git(root, "checkout", "-q", "--detach", rev)
    need(
        git(root, "rev-parse", "HEAD").decode().strip() == rev
        and git(root, "rev-parse", "HEAD^{tree}").decode().strip() == row["tree"],
        "wrong commit or tree",
    )
    for path, sha in row["files"].items():
        full = root / path
        need(
            full.is_file()
            and not full.is_symlink()
            and full.resolve().is_relative_to(root)
            and digest(full.read_bytes()) == sha
            and digest(git(root, "show", rev + ":" + path)) == sha,
            "wrong file at " + rev + ":" + path,
        )


def scan(exe, root, row, profile, *opts):
    p = subprocess.run(
        [exe, "analyze", *sorted(row["files"]), "--profile", profile, "--json", *opts],
        cwd=root,
        capture_output=True,
        timeout=240,
    )
    need(
        p.stdout,
        "scanner did not return JSON: " + p.stderr.decode(errors="replace")[:500],
    )
    got = json.loads(p.stdout)
    need(
        got["project"]["complete"]
        and {f["path"] for f in got["files"]} == set(row["files"]),
        "different native source inventory",
    )
    if profile == NAME:
        s = got.get("partial_rule_selection")
        need(
            s
            and s["profile"] == NAME
            and s["reference_active_rules"] == len(REFERENCE["rules"])
            and s["reference_version"] == REFERENCE["environment"]["version"]
            and s["membership_sha256"] == REFERENCE["scanner_membership_sha256"]
            and s["unmapped_parameter_keys"]
            == sorted(k for k, v in REFERENCE["rules"].items() if v["parameters"])
            and set(s["missing_catalog_keys"]).issubset(REFERENCE["rules"])
            and s["selected_catalog_keys"]
            + len(set(s["missing_catalog_keys"]) | set(s["unmapped_parameter_keys"]))
            == len(REFERENCE["rules"])
            and p.returncode == 2,
            "expected an explicit partial profile",
        )
    else:
        need(
            got.get("partial_rule_selection") is None and p.returncode in (0, 1),
            "invalid legacy scan",
        )
    return got


def primary(path, key, loc, message):
    return (path, key, *loc, message)


def native_hits(report):
    out = Counter()
    for file in report["files"]:
        for item in file["issues"]:
            r = item["range"]
            loc = [
                r[pos][key] for pos in ("start", "end") for key in ("line", "column")
            ]
            out[primary(file["path"], item["rule_key"], loc, item["message"])] += 1
    return out


def export_metadata(ref, exe, root, row, profile, matched):
    proc = subprocess.run(
        [
            exe,
            "analyze",
            *sorted(row["files"]),
            "--profile",
            profile,
            "--format",
            "sonar",
        ],
        cwd=root,
        capture_output=True,
        timeout=240,
    )
    need(proc.returncode == (2 if profile == NAME else 0), "unexpected export exit")
    export = json.loads(proc.stdout)
    definitions = keyed(export["rules"], "id")
    emitted = Counter()
    for hit in export["issues"]:
        p = hit["primaryLocation"]
        pos = p.get("textRange", {})
        loc = [pos.get(k) for k in ("startLine", "startColumn", "endLine", "endColumn")]
        emitted[primary(p["filePath"], hit["ruleId"], loc, p["message"])] += 1
    need(
        not (matched - emitted),
        "Sonar export dropped or altered matched primary locations",
    )
    errors = {}
    for key in sorted({x[1] for x in matched}):
        src = ref["rules"][key]
        actual = definitions[key]
        got = dict(
            type=actual["type"],
            severity=actual["severity"],
            impacts=by_quality(actual["impacts"]),
            clean_code_attribute=actual.get("cleanCodeAttribute"),
        )
        differences = {
            k: {"reference": src[k], "export": v} for k, v in got.items() if src[k] != v
        }
        if differences:
            errors[key] = differences
    return errors


def controls(ref, exe, directory, mirrors, profile):
    deltas = []
    for i, case in enumerate(ref["controls"]):
        root = directory / f"control-{i}"
        root.mkdir()
        restore(root, case, case["repository"], mirrors)
        got = native_hits(scan(exe, root, case, profile))
        if profile != NAME:
            # A diagnostic projection of the legacy output. This does not run a Core profile.
            got = Counter({k: n for k, n in got.items() if k[1] in ref["rules"]})
        expected = Counter(
            primary(r["path"], r["rule"], r["location"], r["message"])
            for r in case["issues"]
        )
        add, missing = got - expected, expected - got
        deltas.append(
            dict(
                repository=case["repository"],
                revision=case["revision"],
                reference=sum(expected.values()),
                matched=sum((expected & got).values()),
                metadata_differences=export_metadata(
                    ref, exe, root, case, profile, expected & got
                ),
                additional=sorted(add.elements()),
                missing=sorted(missing.elements()),
            )
        )
    return deltas


def pairs(ref, exe, directory, mirrors, profile):
    result = []
    for i, pair in enumerate(ref["commander"]):
        root = directory / f"commander-{i}"
        root.mkdir()
        stages = pair["stages"]
        a, b = stages
        baseline = directory / f"baseline-{i}.json"
        period = directory / f"period-{i}.json"
        period.write_text(json.dumps(pair["period"]))
        restore(root, a, pair["repository"], mirrors)
        before = scan(exe, root, a, profile, "--write-baseline", baseline)
        need(
            before["assessment"]["context"]["source_revision"] == a["revision"],
            "wrong native baseline",
        )
        restore(root, b, pair["repository"], mirrors)
        label = pair["label"].rsplit("-", 1)[-1]
        lcov = gzip.decompress(
            (
                HERE.parent / "fixtures/commander-lcov" / (label + ".lcov.gz")
            ).read_bytes()
        )
        need(digest(lcov) == pair["coverage_sha256"], "wrong Commander LCOV bytes")
        rel = ".hoonarqube-coverage.lcov"
        need(not (root / rel).exists(), "unexpected coverage file")
        (root / rel).write_bytes(lcov)
        gate = directory / f"gate-{i}.json"
        gate.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "conditions": [
                        {
                            "scope": "new_code",
                            "metric": "violations",
                            "operator": "lte",
                            "threshold": 0,
                        }
                    ],
                }
            )
        )
        report = scan(
            exe,
            root,
            b,
            profile,
            "--baseline",
            baseline,
            "--specific-analysis",
            period,
            "--quality-gate",
            gate,
            "--coverage-lcov",
            rel,
        )
        assessment = report["assessment"]
        new = assessment["new_code"]
        need(
            assessment["context"]["source_revision"] == b["revision"]
            and new["specific_analysis"] == pair["period"]
            and new["status"] == "complete",
            "incomplete or wrong native period",
        )
        files = {f["path"]: f["issues"] for f in report["files"]}
        keys = Counter(
            files[x["path"]][x["issue_index"]]["rule_key"]
            for x in new["findings"]
            if x["status"] == "new"
        )
        if profile != NAME:
            need(
                dict(keys) == pair["legacy_new_issues"]
                and all(k not in ref["rules"] for k in keys),
                "legacy new-code drift",
            )
        else:
            need(
                not keys
                and assessment["gate"]["status"] == "unavailable"
                and assessment["gate"]["conditions"][0]["actual"] is None,
                "partial scanner claimed a complete gate or added a Commander finding",
            )
        result.append(
            dict(
                period=pair["label"],
                legacy_or_selected_new=dict(keys),
                reference_new=pair["reference_new_issues"],
                gate=assessment["gate"]["status"],
            )
        )
    return result


def guard(current, previous):
    before = keyed(previous["controls"], "repository")
    after = keyed(current["controls"], "repository")
    need(set(after) == set(before), "public control set changed")
    for repo, row in after.items():
        old = before[repo]
        need(
            row["revision"] == old["revision"] and row["reference"] == old["reference"],
            "public reference changed: " + repo,
        )
        for category in ("additional", "missing"):
            actual = Counter(map(tuple, row[category]))
            prior = Counter(map(tuple, old[category]))
            need(not (actual - prior), f"{repo}: new {category} primary locations")
        need(not row["metadata_differences"], repo + ": exported rule metadata differs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scanner", type=Path)
    parser.add_argument(
        "--mirrors",
        type=Path,
        help="JSON object mapping each repository to a local Git mirror",
    )
    parser.add_argument(
        "--mode",
        choices=["legacy-audit", "core-audit", "core-guard", "core-accept"],
        required=True,
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    ref = REFERENCE
    exe = args.scanner.resolve(strict=True)
    mirrors = read(args.mirrors) if args.mirrors else None
    profile = "sonar-parity" if args.mode == "legacy-audit" else NAME
    with tempfile.TemporaryDirectory(prefix="hq-js-core-") as tmp:
        work = Path(tmp).resolve()
        result = {
            "mode": args.mode,
            "scanner_sha256": digest(exe.read_bytes()),
            "commander": pairs(ref, exe, work, mirrors, profile),
            "controls": controls(ref, exe, work, mirrors, profile),
        }
    data = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(data)
    else:
        print(data, end="")
    if args.mode == "core-guard":
        guard(result, read(HERE / "observed.json"))
    if args.mode == "core-accept":
        need(
            all(
                not x["additional"]
                and not x["missing"]
                and not x["metadata_differences"]
                for x in result["controls"]
            ),
            "public findings still differ; see the recorded ranges and messages",
        )


if __name__ == "__main__":
    main()
