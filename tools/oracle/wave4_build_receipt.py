#!/usr/bin/env python3
"""Build the release scanner from committed Git objects and record the resulting bytes."""

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
METHOD = "isolated-cargo-release-v1"
SCANNER = "hoonarqube"


def read(cwd, *command):
    return subprocess.check_output(command, cwd=cwd, text=True).strip()


def git(repo, *args):
    return read(repo, "git", "-c", "core.hooksPath=/dev/null", *args)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_receipt(repo, receipt, *, binary=None, expected_commit=None):
    if receipt.get("build_method") != METHOD or receipt.get("profile") != "release":
        raise ValueError("expected a receipt from a fresh release scanner build")
    commit = receipt.get("source_commit", "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or (
        expected_commit is not None and commit != expected_commit
    ):
        raise ValueError("wrong scanner source commit")
    if receipt.get("source_tree") != git(repo, "rev-parse", f"{commit}^{{tree}}"):
        raise ValueError("wrong scanner source tree")
    sha = receipt.get("binary_sha256", "")
    if not re.fullmatch(r"[0-9a-f]{64}", sha) or (
        binary is not None and digest(binary) != sha
    ):
        raise ValueError("scanner bytes differ from the release build receipt")
    return commit


def compile_scanner(source, target):
    env = {
        **os.environ,
        "CARGO_BUILD_BUILD_DIR": str(target),
        "CARGO_INCREMENTAL": "0",
        "RUSTC_WRAPPER": "",
        "RUSTC_WORKSPACE_WRAPPER": "",
    }
    # Explicit CLI paths override local Cargo settings. Both output and
    # intermediate build artifacts must be private to this invocation.
    command = [
        "cargo",
        "build",
        "--locked",
        "--release",
        "--package",
        "hoonarqube-cli",
        "--bin",
        SCANNER,
        "--target-dir",
        str(target),
        "--message-format=json-render-diagnostics",
    ]
    messages = [
        json.loads(line)
        for line in subprocess.check_output(
            command, cwd=source, env=env, text=True
        ).splitlines()
    ]
    artifacts = [m for m in messages if m["reason"] == "compiler-artifact"]
    bins = [
        m for m in artifacts if m.get("executable") and m["target"]["name"] == SCANNER
    ]
    binary = target / "release" / SCANNER
    if (
        messages[-1] != {"reason": "build-finished", "success": True}
        or any(m["fresh"] for m in artifacts)
        or len(bins) != 1
        or bins[0]["manifest_path"] != str(source / "crates/hoonarqube-cli/Cargo.toml")
        or bins[0]["executable"] != str(binary)
    ):
        raise ValueError("Cargo did not produce a fresh workspace scanner")
    return binary


def build_scanner(repo, output):
    if output.exists() or output.is_symlink():
        raise ValueError(
            "choose a new output directory for the scanner and its receipt"
        )
    commit = git(repo, "rev-parse", "HEAD")
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        scratch = Path(tmp).resolve()
        source = scratch / "source"
        # Source comes only from Git. The caller's ignored files and target cannot enter.
        git(
            scratch,
            "clone",
            "--quiet",
            "--local",
            "--shared",
            "--no-checkout",
            str(repo),
            str(source),
        )
        git(
            source,
            "-c",
            "core.autocrlf=false",
            "checkout",
            "--quiet",
            "--detach",
            commit,
        )
        tree = git(source, "rev-parse", "HEAD^{tree}")
        binary = compile_scanner(source, scratch / "target")
        if (
            git(source, "status", "--porcelain")
            or git(source, "rev-parse", "HEAD") != commit
        ):
            raise ValueError("checkout changed during scanner build")
        receipt = {
            "build_method": METHOD,
            "source_commit": commit,
            "source_tree": tree,
            "binary_sha256": digest(binary),
            "profile": "release",
            "rustc_version": read(source, "rustc", "--version"),
            "cargo_version": read(source, "cargo", "--version"),
            "host": f"{platform.system()}/{platform.machine()}",
        }
        stage = scratch / "output"
        stage.mkdir()
        copied = stage / SCANNER
        shutil.copy2(binary, copied)
        verify_receipt(source, receipt, binary=copied, expected_commit=commit)
        (stage / "build.json").write_text(json.dumps(receipt, indent=2) + "\n")
        stage.rename(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="New directory for hoonarqube and build.json.",
    )
    args = parser.parse_args()
    build_scanner(REPO, args.output_dir.absolute())


if __name__ == "__main__":
    main()
