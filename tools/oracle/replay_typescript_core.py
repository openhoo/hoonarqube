#!/usr/bin/env python3
"""Recheck native TypeScript findings against the pinned public reference observations."""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess

from public_corpus_summary import utf16_coordinates


def read(path):
    return json.loads(path.read_bytes())


def demand(ok, reason):
    if not ok:
        raise ValueError(reason)


def finding(row):
    return row["rule"], row["path"], tuple(row["utf16"]), row["message"]


def tracked(root, *args):
    return subprocess.check_output(["git", "-C", root, *args], text=True).strip()


def check(root, cli, project, snapshot_digest, active_keys):
    def verify_checkout():
        demand(
            tracked(root, "rev-parse", "HEAD") == project["commit"], "commit changed"
        )
        demand(
            tracked(root, "rev-parse", "HEAD^{tree}") == project["tree"], "tree changed"
        )
        demand(
            not tracked(root, "status", "--porcelain", "--untracked-files=all"),
            "dirty checkout",
        )
        paths = tracked(root, "ls-files", "--", project["scope"]).splitlines()
        demand(set(paths) == set(project["files"]), "source inventory changed")
        for name, digest in project["files"].items():
            path = root / name
            demand(
                not path.is_symlink()
                and hashlib.sha256(path.read_bytes()).hexdigest() == digest,
                f"source hash mismatch: {name}",
            )

    verify_checkout()
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in ("HOONARQUBE_TYPESCRIPT_PACKAGE", "NODE_PATH")
    }

    def scan(profile, code):
        run = subprocess.run(
            [
                cli,
                "analyze",
                project["scope"],
                "--format",
                "json",
                "--profile",
                profile,
            ],
            cwd=root,
            env=env,
            capture_output=True,
            timeout=150,
            check=False,
        )
        demand(
            run.returncode == code,
            f"{profile} exit {run.returncode}: {run.stderr.decode()}",
        )
        report = json.loads(run.stdout)
        demand(
            report["project"]["complete"]
            and {f["path"] for f in report["files"]} == set(project["files"]),
            "incomplete native file set",
        )
        verify_checkout()
        return report

    def findings(report):
        result = Counter()
        for file in report["files"]:
            path = file["path"]
            lines = (root / path).read_bytes().decode("utf-8").splitlines()
            for issue in file["issues"]:
                result[
                    issue["rule_key"],
                    path,
                    utf16_coordinates(issue, lines),
                    issue["message"],
                ] += 1
        return result

    legacy = scan("sonar-parity", 0)
    demand(
        legacy["parity"]["semantic_context"]["typescript"]
        == project["native_compiler_context"],
        "TypeScript compiler context changed",
    )
    core = scan("community-26.11-typescript-core", 2)
    selection = core["partial_rule_selection"]
    demand(
        selection["membership_sha256"] == snapshot_digest
        and not selection.get("fallback_languages"),
        "selection or language coverage changed",
    )
    demand(
        core["project"]["metrics"] == legacy["project"]["metrics"],
        "metrics changed across profiles",
    )
    old, new = findings(legacy), findings(core)
    demand(
        old.total() == project["legacy_findings"]
        and sum(n for k, n in old.items() if k[0] not in active_keys)
        == project["removed_inactive_findings"],
        "legacy findings or reference membership changed",
    )
    ref = Counter(map(finding, project["matching"] + project["reference_only"]))
    differences = {
        "matching": ref & new,
        "reference_only": ref - new,
        "native_only": new - ref,
    }
    for key, current in differences.items():
        expected = Counter(map(finding, project[key]))
        demand(
            current == expected,
            f"{key} changed: added {current - expected}; removed {expected - current}",
        )
    return tuple(
        differences[k].total() for k in ("matching", "native_only", "reference_only")
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", required=True, type=Path)
    parser.add_argument(
        "--sources",
        required=True,
        type=Path,
        help="directory of clean checkouts named OWNER-REPO",
    )
    parser.add_argument(
        "--receipt",
        type=Path,
        default=Path(__file__).with_name("typescript-core-s8786-public-26.11.json"),
        help="pinned native/reference observations for this build",
    )
    args = parser.parse_args()
    oracle = Path(__file__).resolve().parent
    receipt = read(args.receipt)
    snapshot = (
        oracle.parents[1] / "catalog/reference/typescript-core-community-26.11.json"
    )
    digest = hashlib.sha256(snapshot.read_bytes()).hexdigest()
    demand(
        digest == receipt["snapshot_sha256"], "snapshot differs from reference receipt"
    )
    for project in receipt["projects"]:
        name = project["repository"]
        try:
            result = check(
                args.sources.resolve() / name.replace("/", "-"),
                args.cli.resolve(),
                project,
                digest,
                set(read(snapshot)["active_keys"]),
            )
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            raise SystemExit(f"{name}: {error}") from error
        print(
            f"{name}: {len(project['files'])} files; matches/native only/reference only: {result}"
        )


if __name__ == "__main__":
    main()
