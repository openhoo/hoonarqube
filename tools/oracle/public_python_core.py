"""Analyze pinned Python files and preserve exact primary locations and messages."""

from collections import Counter
import json
from pathlib import Path
import subprocess
import tempfile

from public_contract import git, require, safe_path, stage


def analyze(binary, root, files, *, cli_options=()):
    proc = subprocess.run(
        [
            binary,
            "analyze",
            *sorted(files),
            "--profile",
            "community-26.11-python-core",
            "--format",
            "json",
            *cli_options,
        ],
        capture_output=True,
        cwd=root,
        timeout=120,
    )
    report = json.loads(proc.stdout)
    require(
        report["project"]["complete"]
        and len(report["files"]) == len(files)
        and {f["path"] for f in report["files"]} == set(files),
        "native inventory changed",
    )
    require(
        proc.returncode == 2
        and report["partial_rule_selection"]["profile"] == "community-26.11-python-core"
        and report["partial_rule_selection"]["reference_version"] == "26.11.0.134175"
        and report["partial_rule_selection"]["reference_active_rules"] == 232,
        "profile completion and exit disagree",
    )
    return Counter(
        (
            i["rule_key"],
            f["path"],
            *[
                i["range"][pos][key]
                for pos in ("start", "end")
                for key in ("line", "column")
            ],
            i["message"],
        )
        for f in report["files"]
        for i in f["issues"]
    )


def package_findings(binary, case, local):
    safe_path(case["repository"])
    if case["scope"] != ".":
        safe_path(case["scope"])
    for path in case["files"]:
        safe_path(path)
    with tempfile.TemporaryDirectory() as tmp:
        root = stage(case, Path(tmp), local)
        entries = (
            git(
                local or Path(tmp) / "objects",
                "ls-tree",
                "-rz",
                "--name-only",
                case["commit"],
                "--",
                case["scope"],
            )
            .decode()
            .split("\0")
        )
        require(
            {p for p in entries if p.endswith(".py")} == set(case["files"]),
            "reference inventory differs from pinned source scope",
        )
        return analyze(binary, root, case["files"])
