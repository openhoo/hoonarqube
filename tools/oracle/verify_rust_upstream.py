#!/usr/bin/env python3
"""Verify Rust upstream-unverified rows against a Sonar plugin and Clippy."""

import argparse
import json
from pathlib import Path

from parity import write_text_atomic
from rust_clippy import verify_upstream_boundaries


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project_dir", type=Path)
    parser.add_argument("plugin_jar", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    report = verify_upstream_boundaries(
        args.project_dir.resolve(), args.plugin_jar.resolve()
    )
    write_text_atomic(args.output.resolve(), json.dumps(report, indent=2) + "\n")
    print(f"verified {len(report['boundaries'])} upstream boundary row(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
