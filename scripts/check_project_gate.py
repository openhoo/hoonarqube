#!/usr/bin/env python3
"""Check a trusted service ingest receipt for the expected project, branch and commit."""

import argparse
import json
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("project", "branch", "commit"):
        parser.add_argument(f"--{flag}", required=True)
    args = parser.parse_args()
    try:
        row = json.load(sys.stdin)["analysis"]
        if any(row[key] != value for key, value in vars(args).items()):
            raise ValueError("receipt is for a different project, branch or commit")
        version = row.get("gate_policy_version")
        if type(version) is not int or version < 1:
            raise ValueError("analysis has no assigned project gate")
        gate = row["gate"]
        if gate["schema_version"] != 3 or not gate["conditions"]:
            raise ValueError("missing or unsupported gate decision")
        status = gate["status"]
        if status not in ("pass", "fail", "unavailable"):
            raise ValueError("unknown gate decision")
    except (KeyError, TypeError, ValueError) as err:
        print(f"Cannot verify assigned gate: {err}", file=sys.stderr)
        return 2
    print(f"Project gate version {version}: {status}")
    return {"pass": 0, "fail": 1, "unavailable": 2}[status]


if __name__ == "__main__":
    sys.exit(main())
