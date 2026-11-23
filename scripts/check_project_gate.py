#!/usr/bin/env python3
"""Check a trusted service receipt for the expected analysis and optional policy version."""

import argparse
import json
import sys


def positive_int(value):
    version = int(value)
    if version < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return version


def gate_status(gate):
    schema = gate["schema_version"]
    conditions = gate["conditions"]
    if (
        type(schema) is not int
        or schema != 3
        or not isinstance(conditions, list)
        or not conditions
    ):
        raise ValueError("missing or unsupported gate decision")

    states = set()
    for condition in conditions:
        state = condition["status"]
        if state not in ("pass", "fail", "unavailable", "no_value"):
            raise ValueError("unknown gate condition state")
        states.add(state)

    # The service gives unavailable priority over fail, and no_value is neutral.
    expected = "pass"
    if "unavailable" in states:
        expected = "unavailable"
    elif "fail" in states:
        expected = "fail"
    status = gate["status"]
    if status != expected:
        raise ValueError("gate decision disagrees with its condition states")
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    identity = ("project", "branch", "commit")
    for flag in identity:
        parser.add_argument(f"--{flag}", required=True)
    parser.add_argument(
        "--policy-version",
        type=positive_int,
        help="require this exact assigned policy version",
    )
    args = parser.parse_args()
    try:
        row = json.load(sys.stdin)["analysis"]
        if any(row[key] != getattr(args, key) for key in identity):
            raise ValueError("receipt is for a different project, branch or commit")
        version = row.get("gate_policy_version")
        if type(version) is not int or version < 1:
            raise ValueError("analysis has no assigned project gate")
        if args.policy_version is not None and version != args.policy_version:
            raise ValueError(
                f"policy version mismatch: expected {args.policy_version}, got {version}"
            )
        status = gate_status(row["gate"])
    except (KeyError, TypeError, ValueError) as err:
        print(f"Cannot verify assigned gate: {err}", file=sys.stderr)
        return 2
    print(f"Project gate version {version}: {status}")
    return {"pass": 0, "fail": 1, "unavailable": 2}[status]


if __name__ == "__main__":
    sys.exit(main())
