#!/usr/bin/env python3
"""Pin bounded source-only checkouts for a fresh public comparison."""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from parity import read_json, write_json_atomic
from public_corpus_prepare import GIT_ENV

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
SELECTION = HERE / "public-corpus-wave4-selection-20261122.tsv"
MANIFEST = HERE / "public-corpus-wave4-projects-20261122.json"
PREFIX = "hq-public-wave4-20261122-"
SHA = re.compile(r"[0-9a-f]{40}")
SAFE_PATH = re.compile(r"[A-Za-z0-9_./@+-]+")
SLUG = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
EXTENSIONS = {
    "go": {".go"},
    "py": {".py"},
    "rust": {".rs"},
    "ruby": {".rb"},
    "js": {".js", ".mjs", ".cjs", ".jsx"},
    "ts": {".ts", ".mts", ".cts", ".tsx"},
}
TEST_DIRS = {
    "tests",
    "test",
    "spec",
    "__tests__",
    "__mocks__",
    "__fixtures__",
    "fixtures",
    "benches",
    "benchmark",
    "benchmarks",
    "testdata",
    "__pycache__",
}
GIB = 1024**3
MAX_SOURCE_FILES = 180
MAX_SOURCE_BYTES = 2 * 1024**2
MAX_GIT_OUTPUT_BYTES = 16 * 1024**2
BASELINE = [
    REPO / "docs/engineering/public-projects-2026-11-21.json",
    *sorted(HERE.glob("public-corpus*-projects-20261120.json")),
    HERE / "public-csharp-pilot-qualification-20261120.json",
]


def historical_identity() -> dict[str, set[str]]:
    answer: dict[str, set[str]] = {
        key: set() for key in ("repository", "commit", "tree")
    }

    def add(obj: Any) -> None:
        if isinstance(obj, list):
            for child in obj:
                add(child)
        elif isinstance(obj, dict):
            for key, value in obj.items():
                if key in answer and isinstance(value, str):
                    answer[key].add(value.casefold())
                elif isinstance(value, (dict, list)):
                    add(value)

    for path in BASELINE:
        add(read_json(path))
    return answer


def fields(selection: Path) -> list[dict]:
    rows = []
    identities = historical_identity()
    for raw in selection.read_text().splitlines():
        if not raw or raw.startswith("#"):
            continue
        language, slug, root = raw.split("\t")
        if language not in EXTENSIONS or not SLUG.fullmatch(slug):
            raise ValueError(f"invalid source selection: {raw}")
        if root != "@root":
            checked_path(root)
        slug = slug.casefold()
        if slug in identities["repository"]:
            raise ValueError(f"repeated or historical repository: {slug}")
        identities["repository"].add(slug)
        name = re.sub(r"[^a-z0-9]+", "-", slug).strip("-")
        rows.append(
            {
                "name": name,
                "repository": slug,
                "language": language,
                "scope_root": root,
                "project_key": PREFIX + name,
                "exclude": [],
            }
        )
    if not rows or len({r["name"] for r in rows}) != len(rows):
        raise ValueError("missing or colliding project names")
    return rows


def checked_path(value: str) -> Path:
    parts = value.split("/")
    if not SAFE_PATH.fullmatch(value) or set(parts) & {"", ".", "..", ".git"}:
        raise ValueError(f"unsafe repository path {value!r}")
    return Path(value)


def matches(path: Path, language: str, root: str) -> bool:
    if not (
        (
            path.parent == Path(".")
            if root == "@root"
            else path.is_relative_to(Path(root))
        )
        and path.suffix in EXTENSIONS[language]
        and not set(path.parts[:-1]) & TEST_DIRS
    ):
        return False
    name = path.name
    return not (
        language == "ts"
        and name.endswith((".d.ts", ".d.mts", ".d.cts"))
        or language == "py"
        and name.startswith("test_")
        or language == "go"
        and name.endswith("_test.go")
        or language in {"js", "ts"}
        and any(t in name for t in (".test.", ".spec.", ".bench."))
    )


def require_disk(state: Path, reserve: int = 0) -> None:
    free = shutil.disk_usage(state).free
    if free < 5 * GIB + reserve:
        raise RuntimeError(f"disk reserve reached: {free / GIB:.2f} GiB free")


def git(
    root: Path,
    *argv: str,
    stdin: bytes | None = None,
    timeout: int = 75,
    allow_lazy_fetch: bool = False,
) -> bytes:
    # The fsize cap applies to each output file (including partial-clone packs).
    command = [
        "/bin/sh",
        "-c",
        'ulimit -f "$1"; shift; exec git "$@"',
        "wave4-git",
        str(MAX_GIT_OUTPUT_BYTES // 512),
        "-c",
        "core.hooksPath=/dev/null",
        *argv,
    ]
    return subprocess.run(
        command,
        cwd=root,
        env={**GIT_ENV, "GIT_NO_LAZY_FETCH": "0" if allow_lazy_fetch else "1"},
        input=stdin,
        capture_output=True,
        check=True,
        timeout=timeout,
    ).stdout


def verify_checkout_paths(root: Path, entries: dict[str, str]) -> None:
    parents = {p for rel in entries for p in checked_path(rel).parents}
    directories = [root]
    while directories:
        for path in directories.pop().iterdir():
            rel = path.relative_to(root)
            if rel == Path(".git"):
                continue
            if not path.is_symlink():
                if rel in parents and path.is_dir():
                    directories.append(path)
                    continue
                if rel.as_posix() in entries and path.is_file():
                    continue
            raise ValueError(f"unexpected path in sparse checkout: {rel}")


def inventory(root: Path, entries: dict[str, str]) -> dict[str, dict]:
    verify_checkout_paths(root, entries)
    observed = {}
    size = 0
    for rel, oid in entries.items():
        path = root / checked_path(rel)
        if path.is_symlink() or not path.is_file() or path.resolve() != path:
            raise ValueError(f"selected source is missing or not regular: {rel}")
        amount = path.stat().st_size
        size += amount
        if size > MAX_SOURCE_BYTES:
            raise ValueError("selected source bytes exceed the per-project limit")
        data = path.read_bytes()
        if (
            hashlib.sha1(
                f"blob {amount}\0".encode() + data, usedforsecurity=False
            ).hexdigest()
            != oid
        ):
            raise ValueError(f"checked out bytes differ from the Git blob: {rel}")
        observed[rel] = {
            "git_blob": oid,
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": amount,
        }
    return observed


def verify_head(root: Path, commit: str, tree: str) -> None:
    git_dir = root / ".git"
    if root.resolve() != root or git_dir.is_symlink() or not git_dir.is_dir():
        raise ValueError("expected an ordinary sparse checkout")
    # Git status (including --ignored) can fetch an unselected .gitignore
    # from a promisor remote. Reading HEAD and its tree needs no source blobs.
    actual = git(root, "rev-parse", "HEAD^{commit}", "HEAD^{tree}", timeout=10)
    if actual.decode().splitlines() != [commit, tree]:
        raise ValueError("checkout does not have the pinned commit and tree")


def source_blobs(root: Path, tree: str, selected: dict) -> dict[str, str]:
    entries = {}
    for entry in git(root, "ls-tree", "-rz", "--full-tree", tree).split(b"\0"):
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split()
        rel = raw_path.decode("utf-8", errors="surrogateescape")
        if not matches(Path(rel), selected["language"], selected["scope_root"]):
            continue
        checked_path(rel)
        if kind != "blob" or mode not in {"100644", "100755"} or not SHA.fullmatch(oid):
            raise ValueError(f"unsafe source tree entry: {rel}")
        entries[rel] = oid
    if not 0 < len(entries) <= MAX_SOURCE_FILES:
        raise ValueError(
            f"selected {len(entries)} files; expected 1–{MAX_SOURCE_FILES}"
        )
    paths = sorted(entries)
    if selected.get("sources", paths) != paths:
        raise ValueError("selected paths differ from the pinned manifest")
    return entries


def verify_sparse_checkout(row: dict) -> Path:
    root = Path(row["path"])
    verify_head(root, row["commit"], row["tree"])
    entries = source_blobs(root, row["tree"], row)
    if inventory(root, entries) != row["source_inventory"]:
        raise ValueError("selected source bytes differ from the pinned manifest")
    return root


def prepare(state: Path, selected: dict) -> dict:
    require_disk(state, reserve=4 * MAX_GIT_OUTPUT_BYTES)
    root = state / "sources" / selected["name"]
    root.mkdir(mode=0o755, exist_ok=False, parents=True)
    remote = f"https://github.com/{selected['repository']}.git"
    git(root, "init", "--quiet", "--template=")
    git(root, "remote", "add", "origin", remote)
    git(root, "config", "remote.origin.promisor", "true")
    git(root, "config", "remote.origin.partialclonefilter", "blob:none")
    git(root, "config", "core.autocrlf", "false")
    git(
        root,
        "fetch",
        "--quiet",
        "--depth=1",
        "--filter=blob:none",
        "--no-tags",
        "origin",
        selected.get("commit", "HEAD"),
    )
    commit = git(root, "rev-parse", "FETCH_HEAD^{commit}").decode().strip()
    tree = git(root, "rev-parse", "FETCH_HEAD^{tree}").decode().strip()
    if not SHA.fullmatch(commit) or not SHA.fullmatch(tree):
        raise ValueError("checkout did not resolve to SHA-1 commit and tree IDs")
    if selected.get("commit", commit) != commit or selected.get("tree", tree) != tree:
        raise ValueError("upstream checkout differs from the pinned commit or tree")
    entries = source_blobs(root, tree, selected)
    paths = sorted(entries)
    git(
        root,
        "sparse-checkout",
        "set",
        "--no-cone",
        "--stdin",
        stdin="".join(f"/{r}\n" for r in paths).encode(),
    )
    git(root, "checkout", "--quiet", "--detach", commit, allow_lazy_fetch=True)
    verify_head(root, commit, tree)
    files = inventory(root, entries)
    if selected.get("source_inventory", files) != files:
        raise ValueError("selected source bytes differ from the pinned manifest")
    result = {
        **selected,
        "path": str(root),
        "commit": commit,
        "ref": commit,
        "tree": tree,
        "sources": paths,
        "source_inventory": files,
    }
    require_disk(state)
    return result


def prepare_all(args) -> int:
    if args.manifest:
        manifest = read_json(args.manifest)
        if manifest["schema_version"] != 1 or manifest["scope"] != "wave4":
            raise ValueError("unexpected public source manifest")
        rows = manifest["projects"]
        candidates = {r["name"]: r for r in fields(args.selection)}
        if len({r["name"] for r in rows}) != len(rows) or any(
            r["name"] not in candidates
            or any(r.get(k) != v for k, v in candidates[r["name"]].items())
            or any(not SHA.fullmatch(r[k]) for k in ("commit", "tree"))
            for r in rows
        ):
            raise ValueError("pinned manifests must match the selection file")
    else:
        rows = fields(args.selection)
    rows = [r for r in rows if not args.language or r["language"] == args.language]
    if not rows:
        raise ValueError("no public source scopes selected")
    state = args.state.resolve()
    (state / "sources").mkdir(mode=0o755, exist_ok=False)
    identities = historical_identity()
    ready, failures = {}, {}
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(prepare, state, row): row for row in rows}
        for future in as_completed(futures):
            row = futures[future]
            key = row["name"]
            try:
                run = future.result()
                if any(run[k] in identities[k] for k in ("commit", "tree")):
                    raise ValueError(
                        "commit or tree already appeared in the public corpus"
                    )
                for k in ("commit", "tree"):
                    identities[k].add(run[k])
                ready[key] = run
                print(key, len(run["sources"]), "prepared", flush=True)
            except (
                OSError,
                RuntimeError,
                ValueError,
                subprocess.SubprocessError,
            ) as error:
                stderr = getattr(error, "stderr", b"") or b""
                failures[key] = {
                    **row,
                    "error": stderr.decode(errors="replace").strip()[-800:]
                    or str(error),
                }
                print(key, failures[key]["error"], flush=True)
            write_json_atomic(
                state / "prepare-progress.json",
                {"prepared": sorted(ready), "failures": failures},
            )
    ordered = [ready[r["name"]] for r in rows if r["name"] in ready]
    write_json_atomic(state / "prepared.json", ordered)
    write_json_atomic(
        state / "pinned.json",
        {
            "schema_version": 1,
            "scope": "wave4",
            "projects": [{k: v for k, v in r.items() if k != "path"} for r in ordered],
        },
    )
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--selection", default=SELECTION, type=Path)
    parser.add_argument(
        "--manifest", type=Path, help="replay an existing pin instead of selecting HEAD"
    )
    parser.add_argument("--language", choices=sorted(EXTENSIONS))
    parser.add_argument("--jobs", type=int, choices=range(1, 5), default=4)
    return prepare_all(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
