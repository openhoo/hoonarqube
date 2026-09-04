#!/usr/bin/env python3
"""Synchronize Hooversion's VERSION into the Cargo workspace manifests."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$"
)
WORKSPACE_VERSION = re.compile(
    r'(?ms)(^\[workspace\.package\]\s*$.*?^version\s*=\s*")[^"]+("\s*$)'
)
INTERNAL_DEPENDENCY = re.compile(
    r'^(\s*hoonarqube(?:-[a-z0-9-]+)?\s*=\s*\{[^}\n]*\bversion\s*=\s*")[^"]+("[^}\n]*\bpath\s*=\s*"\.\./(?:crates/)?hoonarqube[^"\n]*"[^}\n]*\}\s*)$',
    re.MULTILINE,
)
ACTION_DEFAULT = re.compile(r'(?m)^(    default: ")[0-9]+\.[0-9]+\.[0-9]+("\s*)$')
ACTION_DOC_VERSION = re.compile(r"(?m)^(    version: )[0-9]+\.[0-9]+\.[0-9]+(\s*)$")


def synchronized(path: Path, version: str) -> str:
    text = path.read_text(encoding="utf-8")
    if path == ROOT / "Cargo.toml":
        updated, count = WORKSPACE_VERSION.subn(rf"\g<1>{version}\g<2>", text, count=1)
        if count != 1:
            raise RuntimeError(
                "Cargo.toml must contain exactly one [workspace.package] version"
            )
        return updated
    if path.name == "action.yml":
        updated, count = ACTION_DEFAULT.subn(rf"\g<1>{version}\g<2>", text, count=1)
        if count != 1:
            raise RuntimeError(f"{path}: action version default missing or ambiguous")
        return updated
    if path == ROOT / "actions" / "README.md":
        updated, count = ACTION_DOC_VERSION.subn(rf"\g<1>{version}\g<2>", text, count=1)
        if count != 1:
            raise RuntimeError("actions/README.md version example missing or ambiguous")
        return updated
    return INTERNAL_DEPENDENCY.sub(rf"\g<1>{version}\g<2>", text)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check", action="store_true", help="fail instead of rewriting drift"
    )
    args = parser.parse_args()

    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if not SEMVER.fullmatch(version):
        raise RuntimeError("VERSION must contain one unprefixed semantic version")

    paths = [
        ROOT / "Cargo.toml",
        *sorted((ROOT / "crates").glob("*/Cargo.toml")),
        ROOT / "xtask" / "Cargo.toml",
        ROOT / "actions" / "setup" / "action.yml",
        ROOT / "actions" / "analyze" / "action.yml",
        ROOT / "actions" / "code-quality" / "action.yml",
        ROOT / "actions" / "README.md",
    ]
    drifted: list[Path] = []
    for path in paths:
        current = path.read_text(encoding="utf-8")
        updated = synchronized(path, version)
        if current == updated:
            continue
        drifted.append(path.relative_to(ROOT))
        if not args.check:
            path.write_text(updated, encoding="utf-8")

    if args.check and drifted:
        joined = ", ".join(str(path) for path in drifted)
        raise RuntimeError(f"release version drift: {joined}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
