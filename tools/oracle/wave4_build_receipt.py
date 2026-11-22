#!/usr/bin/env python3
"""Describe the clean scanner source and locally built release executable."""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
from pathlib import Path


def read(*command: str) -> str:
    return subprocess.check_output(command, text=True, timeout=30).strip()


def main() -> None:
    if read("git", "status", "--porcelain", "--untracked-files=no"):
        raise ValueError("build receipt requires a clean tracked checkout")
    binary = Path(sys.argv[1]).resolve(strict=True)
    git_tree = read("git", "rev-parse", "HEAD^{tree}")
    with binary.open("rb") as stream:
        binary_sha = hashlib.file_digest(stream, "sha256").hexdigest()
    print(
        json.dumps(
            {
                "source_commit": read("git", "rev-parse", "HEAD"),
                "source_tree": git_tree,
                "compiled_tree": git_tree,
                "binary_sha256": binary_sha,
                "profile": "release",
                "rustc_version": read("rustc", "--version"),
                "cargo_version": read("cargo", "--version"),
                "host": f"{platform.system()}/{platform.machine()}",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
