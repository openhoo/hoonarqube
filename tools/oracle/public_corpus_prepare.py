#!/usr/bin/env python3
"""Prepare Git source pins and isolated Java compiler context for this corpus."""

import argparse
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from parity import read_json, write_json_atomic
from public_corpus_capture import SERVER_IMAGE, verify_checkout
from real_project_suite import digest, run

MANIFEST = Path(__file__).with_name("public-corpus-projects-20261120.json")
MANIFEST_NAMES = {
    "pilot": "pilot-projects.json",
    "captures": "projects.json",
    "additional": "projects-additional-ready.json",
    "aligned": "projects-aligned.json",
}
GIT_ENV = {
    **os.environ,
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_LFS_SKIP_SMUDGE": "1",
}


def prepare_checkout(state, row):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", row["repository"]):
        raise ValueError("public Git repository must use owner/name form")
    if not re.fullmatch(r"[a-z0-9-]+", row["name"]):
        raise ValueError("unexpected public project name")
    if not all(re.fullmatch(r"[0-9a-f]{40}", row[k]) for k in ("commit", "tree")):
        raise ValueError("commit and tree pins must use the full SHA")
    path = state / "sources" / row.get("variant_of", row["name"])
    row = {**row, "path": str(path)}
    if not path.exists():
        path.mkdir(parents=True)

        def git(*args):
            subprocess.run(
                ["git", "-c", "core.hooksPath=/dev/null", *args],
                cwd=path,
                env=GIT_ENV,
                check=True,
                timeout=180,
            )

        git("init", "--quiet")
        git(
            "fetch",
            "--quiet",
            "--depth=1",
            "--no-tags",
            f"https://github.com/{row['repository']}.git",
            row["commit"],
        )
        git("checkout", "--quiet", "--detach", "FETCH_HEAD")
    verify_checkout(row)
    return row


def java_context(state, row):
    root = Path(row["path"])
    folder = state / "java-context" / row["name"]
    classes = folder / "classes"
    classes.mkdir(parents=True, exist_ok=False)
    files = sorted(
        p for source in row["sources"] for p in (root / source).rglob("*.java")
    )
    if not files or any(
        p.is_symlink() or not p.resolve().is_relative_to(root) for p in files
    ):
        raise ValueError("Java scope requires explicit regular source files")
    inputs = [{"path": str(p.relative_to(root)), "sha256": digest(p)} for p in files]
    command = [
        "docker",
        "run",
        "--rm",
        "--network=none",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,noexec",
        "--security-opt=no-new-privileges",
        "--cap-drop=ALL",
        "--memory=1400m",
        "--cpus=1",
        "--user=1000:1000",
        "-v",
        f"{root}:/usr/src:ro",
        "-v",
        f"{classes}:/usr/classes:rw",
        "--entrypoint",
        "/opt/java/openjdk/bin/javac",
        SERVER_IMAGE,
        "-proc:none",
        "-implicit:none",
        "-encoding",
        "UTF-8",
        "--release",
        row["java_release"],
        "-d",
        "/usr/classes",
        *[f"/usr/src/{p.relative_to(root)}" for p in files],
    ]
    run(command, folder, "javac", root)
    outputs = [
        {"path": str(p.relative_to(classes)), "sha256": digest(p)}
        for p in sorted(classes.rglob("*.class"))
    ]
    if not outputs:
        raise ValueError("javac emitted no bytecode")
    verify_checkout(row)
    metadata = folder / "context.json"
    write_json_atomic(
        metadata,
        {
            "inputs": inputs,
            "outputs": outputs,
            "javac_version": "25.0.4.1",
            "javac_image": SERVER_IMAGE,
            "source_release": row["java_release"],
            "annotation_processing": False,
        },
    )
    return {
        **row,
        "java_classes": str(classes),
        "java_context_sha256": digest(metadata),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    args = parser.parse_args()
    os.umask(0o077)
    state = args.state.resolve()
    groups = read_json(args.manifest)
    prepared = []

    def prepare(row):
        selected = prepare_checkout(state, row)
        if "java_release" in selected:
            selected = java_context(state, selected)
        return selected

    for group, rows in groups.items():
        # Variants reuse their already prepared base checkout.
        with ThreadPoolExecutor(max_workers=4 if group == "captures" else 2) as pool:
            results = list(pool.map(prepare, rows))
        write_json_atomic(state / MANIFEST_NAMES[group], results)
        prepared.extend(results)
        print(group, len(results), flush=True)
    write_json_atomic(state / "replay-projects.json", prepared)


if __name__ == "__main__":
    main()
