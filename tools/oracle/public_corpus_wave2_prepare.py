#!/usr/bin/env python3
"""Pin and prepare the second public corpus without running repository scripts."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from parity import read_json, write_json_atomic
from public_corpus_capture import verify_checkout
from public_corpus_prepare import GIT_ENV, java_context

GIB = 1024**3
MAX_SCOPE_FILES = 500
MAX_SCOPE_BYTES = 8 * 1024**2
PLANS = {
    "py": [
        ("itsdangerous", "pallets/itsdangerous", ["src/itsdangerous"]),
        ("packaging", "pypa/packaging", ["src/packaging"]),
        ("trio", "python-trio/trio", ["src/trio"]),
        ("black", "psf/black", ["src/black"]),
        ("async-lru", "aio-libs/async-lru", ["async_lru"]),
        ("more-itertools", "more-itertools/more-itertools", ["more_itertools"]),
    ],
    "go": [
        ("cobra", "spf13/cobra", ["@go-root"]),
        ("websocket", "gorilla/websocket", ["@go-root"]),
        ("cron", "robfig/cron", ["@go-root"]),
        ("testify", "stretchr/testify", ["assert", "require"]),
        ("uuid", "gofrs/uuid", ["@go-root"]),
        ("kong", "alecthomas/kong", ["@go-root"]),
    ],
    "js": [
        ("acorn", "acornjs/acorn", ["acorn/src"]),
        ("jquery", "jquery/jquery", ["src"]),
        ("eslint", "eslint/eslint", ["lib/linter"]),
        ("underscore", "jashkenas/underscore", ["modules"]),
        ("yjs", "yjs/yjs", ["src"]),
        ("picomatch", "micromatch/picomatch", ["index.js", "lib"]),
    ],
    "ts": [
        ("swr", "vercel/swr", ["src"]),
        ("floating-ui", "floating-ui/floating-ui", ["packages/core/src"]),
        ("zustand", "pmndrs/zustand", ["src"]),
        ("react-hook-form", "react-hook-form/react-hook-form", ["src"]),
        ("tanstack-query", "TanStack/query", ["packages/query-core/src"]),
        ("pinia", "vuejs/pinia", ["packages/pinia/src"]),
    ],
    "rust": [
        ("ripgrep", "BurntSushi/ripgrep", ["crates/core"]),
        ("bytes", "tokio-rs/bytes", ["src"]),
        ("crossbeam-channel", "crossbeam-rs/crossbeam", ["crossbeam-channel/src"]),
        ("rayon", "rayon-rs/rayon", ["src"]),
        ("log", "rust-lang/log", ["src"]),
        ("anyhow", "dtolnay/anyhow", ["src"]),
    ],
    "java": [
        ("gson", "google/gson", ["gson/src/main/java"]),
        ("json-java", "stleary/JSON-java", ["src/main/java"]),
        ("jsoup", "jhy/jsoup", ["src/main/java"]),
        ("commons-csv", "apache/commons-csv", ["src/main/java"]),
        ("commons-codec", "apache/commons-codec", ["src/main/java"]),
        (
            "java-diff-utils",
            "java-diff-utils/java-diff-utils",
            ["java-diff-utils/src/main/java"],
        ),
    ],
    "ruby": [
        ("httparty", "jnunemaker/httparty", ["lib"]),
        ("devise", "heartcombo/devise", ["lib"]),
        ("dotenv", "bkeepers/dotenv", ["lib"]),
        ("pundit", "varvet/pundit", ["lib"]),
        ("redis-rb", "redis/redis-rb", ["lib"]),
        ("capybara", "teamcapybara/capybara", ["lib"]),
    ],
}
JAVA_RELEASES = {
    "gson": ("gson-parent-2.8.9", "8"),
    "json-java": ("20250107", "8"),
    "jsoup": ("jsoup-1.16.2", "8"),
    "commons-csv": ("rel/commons-csv-1.8", "8"),
    "commons-codec": ("rel/commons-codec-1.16.1", "8"),
    "java-diff-utils": ("java-diff-utils-parent-4.15", "8"),
}
COMMON_SCRIPT_EXCLUSIONS = [
    "**/__tests__/**",
    "**/__mocks__/**",
    "**/__fixtures__/**",
    "**/*.spec.*",
    "**/*.test.*",
    "**/*.bench.*",
]
EXCLUSIONS = {
    "py": ["**/tests/**", "**/_tests/**", "**/test_*.py"],
    "go": ["**/*_test.go"],
    "js": COMMON_SCRIPT_EXCLUSIONS,
    "ts": COMMON_SCRIPT_EXCLUSIONS,
    "rust": ["**/tests/**", "**/benches/**"],
    "ruby": ["**/test/**", "**/spec/**"],
}


def require_disk(state: Path) -> None:
    free = shutil.disk_usage(state).free
    if free < 5 * GIB:
        raise RuntimeError(f"disk reserve reached: {free / GIB:.2f} GiB free")


def plan_rows():
    for language, specs in PLANS.items():
        for name, repository, sources in specs:
            row = {
                "name": name,
                "repository": repository,
                "language": language,
                "sources": sources,
                "exclude": EXCLUSIONS.get(language, []),
                "selection_ref": "HEAD",
                "project_key": f"hq-public-wave2-20261120-{name}",
            }
            if name in JAVA_RELEASES:
                tag, release = JAVA_RELEASES[name]
                row.update(selection_ref=f"refs/tags/{tag}", java_release=release)
            yield row


def checkout(state: Path, selected: dict) -> dict:
    row = dict(selected)
    require_disk(state)
    name = row["name"]
    if not re.fullmatch(r"[a-z0-9-]+", name) or not re.fullmatch(
        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", row["repository"]
    ):
        raise ValueError("invalid public project identity")
    pin = row.get("commit")
    if pin and not all(
        re.fullmatch(r"[0-9a-f]{40}", row[k]) for k in ("commit", "tree")
    ):
        raise ValueError(f"{name}: pin must include full commit and tree SHAs")
    root = state / "sources" / name
    root.mkdir(parents=True)
    row["path"] = str(root)

    def git(*args):
        result = subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", *args],
            cwd=root,
            env=GIT_ENV,
            check=True,
            capture_output=True,
            timeout=90,
        )
        return result.stdout.decode()

    git("init", "--quiet", "--template=")
    git(
        "fetch",
        "--quiet",
        "--no-tags",
        "--depth=1",
        f"https://github.com/{row['repository']}.git",
        pin or row["selection_ref"],
    )
    row["commit"] = git("rev-parse", "FETCH_HEAD^{commit}").strip()
    row["tree"] = git("rev-parse", "FETCH_HEAD^{tree}").strip()
    if pin and (row["commit"] != pin or row["tree"] != selected["tree"]):
        raise ValueError(f"{name}: fetched commit/tree differs from pinned manifest")
    row["ref"] = row["commit"]
    git("checkout", "--quiet", "--detach", row["commit"])
    tracked = [Path(p) for p in git("ls-files", "-z").rstrip("\0").split("\0") if p]
    if row["sources"] == ["@go-root"]:
        row["sources"] = [
            p.as_posix()
            for p in tracked
            if p.parent == Path(".")
            and p.suffix == ".go"
            and not p.name.endswith("_test.go")
        ]
    scope = [Path(n) for n in row["sources"]]
    if not scope or not all(
        (root / p).exists() and (root / p).resolve().is_relative_to(root) for p in scope
    ):
        raise ValueError(f"{name}: declared source scope missing")
    files = [p for p in tracked if any(p.is_relative_to(parent) for parent in scope)]
    if not files or any(
        not (root / p).is_file() or (root / p).resolve() != root / p for p in files
    ):
        raise ValueError(f"{name}: scope has missing or non-regular tracked files")
    size = sum((root / p).stat().st_size for p in files)
    if len(files) > MAX_SCOPE_FILES or size > MAX_SCOPE_BYTES:
        raise ValueError(f"{name}: scope needs {len(files)} files and {size} bytes")
    verify_checkout(row)
    row["preflight_scope_inventory"] = {
        "tracked_files_in_roots": len(files),
        "bytes": size,
    }
    return row


def finish_projects(state: Path, rows: list[dict]) -> None:
    prepared = []
    for row in rows:
        try:
            require_disk(state)
            if row.get("java_release"):
                row = java_context(state, row)
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
            detail = (
                error.stderr.decode(errors="replace")
                if isinstance(error, subprocess.CalledProcessError)
                and isinstance(error.stderr, bytes)
                else str(error)
            )
            row = {
                **row,
                "reference_excluded": f"Java bridge preflight failed: {detail[:300]}",
            }
            print(row["name"], row["reference_excluded"], flush=True)
        prepared.append(row)
        write_json_atomic(state / "projects-ready-partial.json", prepared)
    pilot = [r for r in prepared if r["name"] == "itsdangerous"]
    if len(pilot) != 1:
        raise RuntimeError("wave2 pilot was not prepared")
    write_json_atomic(state / "pilot-projects.json", pilot)
    write_json_atomic(
        state / "projects.json", [r for r in prepared if r["name"] != "itsdangerous"]
    )
    write_json_atomic(state / "replay-projects.json", prepared)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument(
        "--manifest", type=Path, help="reproduce exact commit and tree pins"
    )
    parser.add_argument(
        "--java",
        action="store_true",
        help="prepare direct javac context for already pinned sources",
    )
    args = parser.parse_args()
    state = args.state.resolve()
    os.umask(0o077)
    if args.java:
        finish_projects(state, read_json(state / "projects-pinned.json"))
        return
    plans = read_json(args.manifest)["projects"] if args.manifest else list(plan_rows())
    assert len(plans) == len({r["repository"].casefold() for r in plans}) == 42
    write_json_atomic(state / "projects-planned.json", plans)
    packed = {}
    with ThreadPoolExecutor(max_workers=2) as pool:
        tasks = {pool.submit(checkout, state, row): row for row in plans}
        for item in as_completed(tasks):
            row = tasks[item]
            name = row["name"]
            try:
                packed[name] = item.result()
                status = f"{packed[name]['commit'][:10]} {packed[name]['preflight_scope_inventory']['tracked_files_in_roots']} files"
            except (
                OSError,
                RuntimeError,
                ValueError,
                subprocess.SubprocessError,
            ) as error:
                detail = (
                    error.stderr.decode(errors="replace")
                    if isinstance(error, subprocess.CalledProcessError)
                    and isinstance(error.stderr, bytes)
                    else str(error)
                )
                packed[name] = {**row, "preflight_error": detail[:500]}
                status = packed[name]["preflight_error"]
            print(name, status, flush=True)
            write_json_atomic(state / "checkout-receipts.json", packed)
    successful = [
        packed[row["name"]]
        for row in plans
        if "preflight_error" not in packed[row["name"]]
    ]
    write_json_atomic(state / "projects-pinned.json", successful)
    print(f"Pinned {len(successful)} of {len(plans)} planned projects.", flush=True)
    return 0 if len(successful) >= 35 else 2


if __name__ == "__main__":
    raise SystemExit(main())
