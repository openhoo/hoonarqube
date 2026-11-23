"""Replay assigned gates on the indexed (and unindexed) bytes of a pinned language sample."""

import argparse
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path

from public_scope_gate import assigned, require, scan
from wave4_prepare import git, verify_head

REFERENCE = Path(__file__).with_name("fixtures") / "linguist-community-scope-2611.json"
REMOTE = "https://github.com/github-linguist/linguist.git"
CONTROL = "samples/JavaScript/hello.js"
NATIVE = {CONTROL, "samples/HTML/pages.html"}
POLICY = {
    "schema_version": 1,
    "conditions": [
        {"metric": "files", "scope": "overall", "operator": "lte", "threshold": 1}
    ],
}


def validate_reference(r):
    full, scoped = r["cases"]["mixed"], r["cases"]["control"]
    require(
        r["community_version"] == "26.11.0.134175"
        and r["github_id"] == 1725199
        and r["repository"] == "github-linguist/linguist"
        and r["commit"] == "cfd7a0113aa1efab99faeff38756f0ed4d48add8"
        and r["tree"] == "5ee09afd58c8f2a51e70e674aac9769658dd3cdb",
        "reference identity",
    )
    require(
        (r["gate"]["metric"], r["gate"]["comparator"], r["gate"]["error"])
        == ("files", "GT", "1"),
        "assigned condition",
    )
    require(
        full["project_key"] != scoped["project_key"]
        and full["task"] != scoped["task"]
        and full["analysis"] != scoped["analysis"],
        "distinct analyses",
    )
    require(
        len(r["files"]) == 20
        and len(full["indexed"]) == full["actual_files"] == 15
        and full["status"] == "ERROR"
        and not full["exclusions"]
        and set(full["indexed"]) <= set(r["files"])
        and full["indexed"][CONTROL] == "js"
        and scoped["indexed"] == {CONTROL: "js"}
        and scoped["actual_files"] == 1
        and scoped["status"] == "OK"
        and set(scoped["exclusions"]) == set(r["files"]) - {CONTROL},
        "indexed or excluded scope changed",
    )
    for name, spec in r["files"].items():
        require(
            name.startswith("samples/")
            and all(
                re.fullmatch(r"[A-Za-z0-9_. -]+", part)
                and part not in {".", "..", ".git"}
                for part in name.split("/")
            )
            and re.fullmatch(r"[a-f0-9]{40}", spec["git_blob"])
            and re.fullmatch(r"[a-f0-9]{64}", spec["sha256"])
            and 0 < spec["bytes"] < 1024**2,
            "unexpected sample entry",
        )
        lang = full["indexed"].get(name)
        if lang and name not in NATIVE and Path(name).name != "Dockerfile":
            suffixes = r["extension_settings"][f"sonar.{lang}.file.suffixes"]
            require(
                Path(name).suffix[1:] in {x.lstrip(".") for x in suffixes},
                f"no suffix proof for {name}",
            )


def select(repo, ref, names, first=False):
    git(
        repo,
        "sparse-checkout",
        "set",
        "--no-cone",
        "--stdin",
        stdin="".join("/" + n + "\n" for n in names).encode(),
        allow_lazy_fetch=True,
    )
    if first:
        git(
            repo,
            "checkout",
            "--detach",
            "--quiet",
            ref["commit"],
            allow_lazy_fetch=True,
        )
    verify_head(repo, ref["commit"], ref["tree"])
    physical = set()
    for root, dirs, files in os.walk(repo):
        directory = Path(root)
        if directory == repo:
            dirs.remove(".git")
        require(
            not any((directory / d).is_symlink() for d in dirs),
            "unexpected directory symlink",
        )
        physical.update((directory / f).relative_to(repo).as_posix() for f in files)
    require(physical == set(names), "sparse source set changed")
    for name in names:
        p = repo / name
        spec = ref["files"][name]
        require(
            not p.is_symlink()
            and p.stat().st_size == spec["bytes"]
            and hashlib.sha256(p.read_bytes()).hexdigest() == spec["sha256"],
            f"wrong bytes: {name}",
        )
        row = git(repo, "ls-tree", "HEAD", "--", name).decode().split("\t", 1)[0]
        require(row == "100644 blob " + spec["git_blob"], f"wrong tree entry: {name}")


def checkout(work, r, local):
    repo = work / "src"
    repo.mkdir()
    git(repo, "init", "--quiet")
    if local:
        verify_head(local, r["commit"], r["tree"])
        store = (
            git(local, "rev-parse", "--path-format=absolute", "--git-path", "objects")
            .decode()
            .strip()
        )
        require(
            "\n" not in store and Path(store).is_dir(), "invalid mirror object store"
        )
        (repo / ".git/objects/info/alternates").write_text(store + "\n")
        (repo / ".git/shallow").write_text(r["commit"] + "\n")
    else:
        git(repo, "remote", "add", "origin", REMOTE)
        git(
            repo,
            "fetch",
            "--quiet",
            "--depth=1",
            "--no-tags",
            "--filter=blob:none",
            "origin",
            r["commit"],
        )
    git(repo, "sparse-checkout", "init", "--no-cone")
    select(repo, r, r["files"], first=True)
    return repo


def inspect_case(cli, repo, policy, paths, opts, expected, rows):
    code, report = scan(cli, repo, paths, [*opts, "--quality-gate", policy])
    gate = report["assessment"]["gate"]
    (condition,) = gate["conditions"]
    require(
        (gate["status"], code, condition["actual"]) == expected,
        f"gate {gate['status']}, exit {code}, actual {condition['actual']}",
    )
    require(report["project"]["complete"] == (code != 2), "completeness")
    observed = {
        Path(f["path"]).as_posix(): (f["classification"], f["status"])
        for f in report["project"]["files"]
    }
    require(
        observed == rows and len(rows) == len(report["project"]["files"]),
        f"inventory {observed}",
    )
    _, raw = scan(cli, repo, paths, [*opts, "--assessment"])
    return raw, gate, code


def replay(cli, repo, policy, r):
    indexed = r["cases"]["mixed"]["indexed"]
    complete = ("source", "complete")
    incomplete = ("source", "unsupported")
    excluded = ("excluded", "excluded")
    cases = {}
    errors = []

    def record(label, paths, opts, expected, rows):
        try:
            cases[label] = inspect_case(cli, repo, policy, paths, opts, expected, rows)
        except ValueError as err:
            errors.append(f"{label}: {err}")

    rows = {p: complete if p in NATIVE else incomplete for p in indexed}
    record("mixed", ["."], [], ("unavailable", 2, None), rows)
    record("overlap", [".", *indexed], [], ("unavailable", 2, None), rows)
    opts = [
        arg
        for name in r["cases"]["control"]["exclusions"]
        for arg in ("--exclude", name)
    ]
    record(
        "control",
        ["."],
        opts,
        ("pass", 0, 1),
        {p: complete if p == CONTROL else excluded for p in r["files"]},
    )
    for name in sorted(set(r["files"]) - {CONTROL}):
        select(repo, r, [CONTROL, name])
        pair = {CONTROL: complete}
        expected = ("pass", 0, 1)
        if name in NATIVE:
            pair[name] = complete
            expected = ("fail", 1, 2)
        elif name in indexed:
            pair[name] = incomplete
            expected = ("unavailable", 2, None)
        label = Path(name).name.replace(".", "-")
        record(label, ["."], [], expected, pair)
        if name in indexed:
            record(
                label + "-excluded",
                ["."],
                ["--exclude", name],
                ("pass", 0, 1),
                {CONTROL: complete, name: excluded},
            )
    require(not errors, "\n".join(errors))
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binaries", type=Path)
    parser.add_argument(
        "--repository", type=Path, help="optional local pinned source mirror"
    )
    args = parser.parse_args()
    ref = json.loads(REFERENCE.read_bytes())
    validate_reference(ref)
    with tempfile.TemporaryDirectory() as td:
        work = Path(td).resolve()
        repo = checkout(work, ref, args.repository)
        policy = work / "policy.json"
        policy.write_text(json.dumps(POLICY))
        bins = args.binaries.resolve()
        cases = replay(bins / "hoonarqube", repo, policy, ref)
        assigned(bins / "hoonarqube-service", work, POLICY, ref["commit"], cases)
        print(
            f"{len(ref['files'])} public files; 15 indexed, 5 absent; {len(cases)} assigned gate decisions, CI exits and restart verified."
        )


if __name__ == "__main__":
    main()
