"""Exercise the no-measurement gate on sparse checkouts from three Jupyter projects."""

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

from community_new_duplication import git
from public_coverage_gate_replay import check, sha256

CAPTURE = Path(__file__).with_name("fixtures") / "notebook-directory-2611.json"


def select(root, case, files):
    git(root, "sparse-checkout", "set", "--no-cone", *("/" + f for f in files))
    git(root, "checkout", "-q", "--detach", case["commit"])
    check(
        git(root, "rev-parse", "HEAD", "HEAD^{tree}").decode().splitlines()
        == [case["commit"], case["tree"]],
        "different public revision",
    )
    actual = {
        p.relative_to(root).as_posix(): sha256(p)
        for p in root.rglob("*")
        if ".git" not in p.relative_to(root).parts
        and p.is_file()
        and not p.is_symlink()
    }
    check(actual == files, "scope or file digest changed")


def scan(root, binary, policy, paths, expected_exit, measured, *options):
    proc = subprocess.run(
        [
            binary,
            "analyze",
            *paths,
            "--profile",
            "sonar-parity",
            "--quality-gate",
            policy,
            *options,
            "--format",
            "json",
        ],
        cwd=root,
        capture_output=True,
        timeout=60,
        check=False,
    )
    report = json.loads(proc.stdout)
    gate = report["assessment"]["gate"]
    check(
        proc.returncode == expected_exit
        and gate["status"] == ("pass" if expected_exit == 0 else "unavailable")
        and gate["conditions"][0]["actual"] == (0 if expected_exit == 0 else None)
        and {Path(row["path"]).as_posix() for row in report["files"]} == set(measured),
        f"{root.name}: unexpected decision or measured scope: {paths}",
    )


def replay(work, binary, local, case):
    repo = case["full_name"]
    check(
        repo in {"jupyter/nbformat", "jupyter/nbconvert", "jupyter/nbclient"},
        "unknown repository",
    )
    root = work / repo.split("/")[1]
    git(work, "init", "-q", str(root))
    source = str(local / root.name) if local else f"https://github.com/{repo}.git"
    git(root, "fetch", "-q", "--no-tags", "--depth=1", source, case["commit"])
    policy = work / "gate.json"
    files = case["files"]
    check(
        case["reference_languages"] == dict.fromkeys(files, "ipynb"),
        "reference scope differs",
    )
    select(root, case, files)
    scan(root, binary, policy, sorted(files), 2, [])
    scan(root, binary, policy, ["."], 2, [])
    select(root, case, files | case["mixed_control"])
    scan(root, binary, policy, ["."], 2, case["mixed_control"])
    scan(
        root, binary, policy, ["."], 0, case["mixed_control"], "--exclude", "**/*.ipynb"
    )
    print(
        f"{repo} {case['commit']}: explicit 2, directory 2, mixed 2, deliberately excluded notebooks 0"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--local-sources", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    local = args.local_sources.resolve(strict=True) if args.local_sources else None
    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        (work / "gate.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "conditions": [
                        {
                            "scope": "overall",
                            "metric": "duplicated_lines",
                            "operator": "lte",
                            "threshold": 0,
                        }
                    ],
                }
            )
        )
        for case in json.loads(CAPTURE.read_bytes()):
            replay(work, binary, local, case)


if __name__ == "__main__":
    main()
