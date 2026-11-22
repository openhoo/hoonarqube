#!/usr/bin/env python3
"""Compare a candidate CLI to captured Sonar primary locations in pinned Git blobs."""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from public_corpus_summary import canonical_sha, normalize_native

MANIFEST = Path(__file__).with_name("public_contract.json")
SOURCE_EXTENSIONS = {".go", ".html", ".java", ".js", ".py", ".rb", ".rs", ".ts"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def safe_path(value):
    parts = value.split("/")
    require(
        all(re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9_.-]*", s) for s in parts),
        f"unsafe relative path: {value!r}",
    )
    return value


def validate_scope(case):
    repo = case["repository"]
    require(len(repo.split("/")) == 2, f"invalid GitHub repository: {repo}")
    safe_path(repo)
    for field in ("commit", "tree"):
        require(re.fullmatch("[0-9a-f]{40}", case[field]), f"invalid {field}")
    roots, files = case["sources"], case["files"]
    require(
        roots and files and len(roots) == len(set(roots)), "empty or duplicate roots"
    )
    for root in roots:
        if root != ".":
            safe_path(root)
    for path, digest in files.items():
        safe_path(path)
        require(
            Path(path).suffix in SOURCE_EXTENSIONS
            and "node_modules" not in Path(path).parts,
            f"not a project source document: {path}",
        )
        require(
            any(
                root == "." or path == root or path.startswith(root + "/")
                for root in roots
            ),
            f"path outside analysis roots: {path}",
        )
        require(re.fullmatch("[0-9a-f]{64}", digest), f"invalid source digest: {path}")
    require(
        canonical_sha(files) == case["source_inventory_sha256"],
        "source inventory digest mismatch",
    )


def validate(case):
    validate_scope(case)
    files = case["files"]
    rules = case["parameters"]
    expected = case["primaries"]
    require(
        expected and {p[0] for p in expected} == set(rules),
        "empty or uncovered contract rule",
    )
    for key, path, sl, sc, el, ec in expected:
        require(
            path in files
            and all(type(n) is int for n in (sl, sc, el, ec))
            and min(sl, el) >= 1
            and min(sc, ec) >= 0
            and (sl, sc) <= (el, ec),
            f"invalid expected primary: {key} {path}",
        )


def git(repo, *args):
    # No hooks, checkout filters, submodules, credentials or user URL rewrites.
    return subprocess.check_output(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "credential.helper=",
            "-C",
            str(repo),
            *args,
        ],
        env={
            "PATH": os.defpath,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "LC_ALL": "C",
        },
        timeout=120,
    )


def stage(case, scratch, local_repo=None):
    commit = case["commit"]
    if local_repo is None:
        repo = scratch / "objects"
        repo.mkdir()
        git(repo, "init", "--quiet", "--bare", "--template=")
        git(
            repo,
            "fetch",
            "--quiet",
            "--depth=1",
            "--no-tags",
            "--no-recurse-submodules",
            "https://github.com/" + case["repository"] + ".git",
            commit,
        )
        revision = "FETCH_HEAD"
    else:
        repo, revision = local_repo, "HEAD"
    require(
        git(repo, "rev-parse", revision + "^{commit}").decode().strip() == commit,
        "wrong commit",
    )
    require(
        git(repo, "rev-parse", commit + "^{tree}").decode().strip() == case["tree"],
        "wrong tree",
    )
    source = scratch / "source"
    source.mkdir()
    files = case["files"]
    entries = git(repo, "--literal-pathspecs", "ls-tree", "-rz", commit, "--", *files)
    seen = set()
    for entry in entries.split(b"\0"):
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        mode, kind, oid = metadata.split()
        path = raw_path.decode()
        require(path in files and path not in seen, f"unexpected Git path: {path}")
        require(
            mode in (b"100644", b"100755") and kind == b"blob",
            f"not a regular blob: {path}",
        )
        body = git(repo, "cat-file", "blob", oid.decode())
        require(
            hashlib.sha256(body).hexdigest() == files[path],
            f"wrong source bytes: {path}",
        )
        destination = source / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(body)
        seen.add(path)
    require(seen == set(files), f"missing Git source: {sorted(files.keys() - seen)}")
    return source


def observe(case, report, source):
    project, parity = report["project"], report["parity"]
    require(
        project["complete"] and not parity["rule_set_violations"],
        "incomplete native scan or rule-set violation",
    )
    require(parity["reference"]["profile"] == "sonar-parity", "wrong native profile")
    scope = parity["scope"]
    require(
        scope["roots"] == case["sources"] and scope["exclude"] == case["exclude"],
        "wrong effective scope",
    )
    require(
        parity["semantic_context"] == case["semantic_context"],
        "different semantic context",
    )
    files = case["files"]
    for rows in (report["files"], project["files"]):
        require(
            Counter(f["path"] for f in rows) == Counter(files.keys()),
            "native file inventory mismatch",
        )
    require(
        all(
            f["status"] == "complete" and f["classification"] == "source"
            for f in project["files"]
        ),
        "incomplete or reclassified source",
    )
    rules = case["parameters"]
    active = {
        r["key"]: {
            p["key"]: p["default_value"]
            for p in r["parameters"]
            if p.get("default_value") is not None
        }
        for r in parity["active_rules"]
    }
    for key, params in rules.items():
        require(
            active.get(key) == params, f"different or inactive rule parameters: {key}"
        )
    selected = [
        {**file, "issues": [i for i in file["issues"] if i["rule_key"] in rules]}
        for file in report["files"]
    ]
    found, _, _, invalid = normalize_native(selected, source, {}, {})
    require(not invalid, f"invalid primary ranges: {dict(invalid)}")
    return found


def compare(case, report, source):
    found = observe(case, report, source)
    expected = Counter(map(tuple, case["primaries"]))
    require(
        found == expected,
        f"primary mismatch: missing={dict(expected - found)}, unexpected={dict(found - expected)}",
    )


def scan(case, binary, local_repo, evaluate):
    with tempfile.TemporaryDirectory(prefix="public-contract-") as directory:
        scratch = Path(directory)
        source = stage(case, scratch, local_repo)
        empty = scratch / "empty"
        empty.mkdir()
        args = [
            binary,
            "analyze",
            *case["sources"],
            "--profile",
            "sonar-parity",
            "--format",
            "json",
        ]
        for pattern in case["exclude"]:
            args.extend(["--exclude", pattern])
        result = subprocess.run(
            args,
            cwd=source,
            check=True,
            stdout=subprocess.PIPE,
            timeout=120,
            env={
                "PATH": str(empty),
                "HOME": str(empty),
                "TMPDIR": str(scratch),
                "LC_ALL": "C",
            },
        )
        return evaluate(case, json.loads(result.stdout), source)


def replay(case, binary, local_repo=None):
    validate(case)
    return scan(case, binary, local_repo, compare)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument(
        "--local-sources",
        type=Path,
        help="optional JSON map of GitHub repository to exact local checkout",
    )
    parser.add_argument("--project", help="run one named project")
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_bytes())
    cases = manifest["projects"]
    require(manifest["format"] == 1 and len(cases) >= 20, "missing public contracts")
    for field in ("name", "repository"):
        require(
            len({c[field].casefold() for c in cases}) == len(cases),
            f"duplicate {field}",
        )
    selected = [c for c in cases if not args.project or c["name"] == args.project]
    require(selected, "unknown project")
    local = json.loads(args.local_sources.read_bytes()) if args.local_sources else None
    for case in selected:
        try:
            replay(
                case,
                args.binary.resolve(),
                local[case["repository"]] if local is not None else None,
            )
        except (ValueError, OSError, subprocess.SubprocessError) as exc:
            sys.exit(f"{case['name']}: {exc}")
        print(
            f"{case['name']}: {len(case['files'])} files; {len(case['parameters'])} rules; "
            f"{len(case['primaries'])} Sonar primaries",
            flush=True,
        )
    print(f"Verified {len(selected)} pinned public repositories.")


if __name__ == "__main__":
    main()
