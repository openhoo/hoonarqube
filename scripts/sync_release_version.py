#!/usr/bin/env python3
"""Synchronize Hooversion's VERSION into the Cargo workspace manifests."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SEMVER_IDENTIFIER = r"(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
BUILD_IDENTIFIER = r"[0-9A-Za-z-]+"
SEMVER_TEXT = (
    rf"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    rf"(?:-{SEMVER_IDENTIFIER}(?:\.{SEMVER_IDENTIFIER})*)?"
    rf"(?:\+{BUILD_IDENTIFIER}(?:\.{BUILD_IDENTIFIER})*)?"
)
SEMVER = re.compile(rf"^{SEMVER_TEXT}$")
WORKSPACE_VERSION = re.compile(
    r'(?ms)(^\[workspace\.package\]\s*$.*?^version\s*=\s*")[^"]+("\s*$)'
)
INTERNAL_DEPENDENCY = re.compile(
    r"(?ms)^[ \t]*hoonarqube(?:-[a-z0-9-]+)?[ \t]*=[ \t]*\{"
    r'(?=[^}]*\bpath\s*=\s*"\.\./(?:crates/)?hoonarqube[^"\n]*")'
    r'(?=[^}]*\bversion\s*=\s*"[^"]+")[^}]*\}'
)
ACTION_DEFAULT = re.compile(rf'(?m)^(    default: "){SEMVER_TEXT}("\s*)$')
ACTION_DOC_VERSION = re.compile(rf"(?m)^(    version: ){SEMVER_TEXT}(\s*)$")


def _replace_internal_dependency(match: re.Match[str], version: str) -> str:
    updated, count = re.subn(
        r'(\bversion\s*=\s*")[^"]+(")',
        rf"\g<1>{version}\g<2>",
        match.group(0),
        count=1,
    )
    if count != 1:
        raise RuntimeError("internal dependency version is missing or ambiguous")
    return updated


def _validate_version(version: str) -> None:
    if not isinstance(version, str) or not SEMVER.fullmatch(version):
        raise RuntimeError("release version must be a valid semantic version")


def synchronized(path: Path, version: str) -> str:
    _validate_version(version)
    text = path.read_text(encoding="utf-8")
    if path == ROOT / "Cargo.toml":
        updated, count = WORKSPACE_VERSION.subn(rf"\g<1>{version}\g<2>", text)
        if count != 1:
            raise RuntimeError(
                "Cargo.toml must contain exactly one [workspace.package] version"
            )
        return updated
    if path.name == "action.yml":
        updated, count = ACTION_DEFAULT.subn(rf"\g<1>{version}\g<2>", text)
        if count != 1:
            raise RuntimeError(f"{path}: action version default missing or ambiguous")
        return updated
    if path == ROOT / "actions" / "README.md":
        updated, count = ACTION_DOC_VERSION.subn(rf"\g<1>{version}\g<2>", text)
        if count == 0:
            raise RuntimeError("actions/README.md has no version example")
        return updated
    return INTERNAL_DEPENDENCY.sub(
        lambda match: _replace_internal_dependency(match, version), text
    )


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
