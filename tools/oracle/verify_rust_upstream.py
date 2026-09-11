#!/usr/bin/env python3
"""Verify Rust upstream-unverified rows against a Sonar plugin and Clippy."""

import argparse
import json
from pathlib import Path

from parity import input_paths_sha256, write_text_atomic
from reference_provenance import (
    file_metadata,
    git_provenance,
    manifest_digest,
    tool_versions,
)
from rust_clippy import verify_upstream_boundaries


REPO = Path(__file__).resolve().parent.parent.parent


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project_dir", type=Path)
    parser.add_argument("plugin_jar", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    plugin_path = Path(args.plugin_jar)
    if plugin_path.is_symlink():
        raise ValueError(f"Rust plugin must not be a symlink: {plugin_path}")
    plugin_path = plugin_path.resolve()
    report = verify_upstream_boundaries(args.project_dir.resolve(), plugin_path)
    provenance = {
        "schema_version": 1,
        "repository": git_provenance(REPO),
        "project_input_sha256": input_paths_sha256(REPO, [args.project_dir]),
        "catalog": file_metadata(REPO / "catalog/rules/rust.json", root=REPO),
        "plugin": file_metadata(plugin_path),
        "tools": tool_versions(include_rust=True),
    }
    provenance["manifest_sha256"] = manifest_digest(provenance)
    report["provenance"] = provenance
    write_text_atomic(args.output.resolve(), json.dumps(report, indent=2) + "\n")
    print(f"verified {len(report['boundaries'])} upstream boundary row(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
