"""Wrap the native JSON report for the service, preserving its exact bytes."""

import argparse
import json
from pathlib import Path
import sys

# The default standalone service accepts this many bytes for the whole HTTP body.
MAX_BODY_BYTES = 16 * 1024 * 1024


def reject_constant(_):
    raise ValueError("invalid JSON number")


def write_envelope(report_path, branch, commit, analyzed_at, output):
    metadata = {
        "schema_version": 1,
        "branch": branch,
        "commit": commit,
        "analyzed_at": analyzed_at,
    }
    prefix = (
        json.dumps(metadata, separators=(",", ":")).encode("ascii")[:-1] + b',"report":'
    )
    suffix = b"}"
    budget = MAX_BODY_BYTES - len(prefix) - len(suffix)
    if budget < 0:
        raise ValueError("upload metadata exceeds the 16 MiB request limit")
    with report_path.open("rb") as file:
        body = file.read(budget + 1)
    if len(body) > budget:
        raise ValueError(
            "analysis upload exceeds 16 MiB; the report has not been modified"
        )
    try:
        report = json.loads(body.decode("utf-8"), parse_constant=reject_constant)
    except (ValueError, RecursionError) as exc:
        raise ValueError("expected one UTF-8 native JSON report") from exc
    if (
        not isinstance(report, dict)
        or type(report.get("schema_version")) is not int
        or report["schema_version"] != 1
        or not isinstance(report.get("files"), list)
        or not isinstance(report.get("project"), dict)
    ):
        raise ValueError("expected a schema 1 native report with files and project")
    # Re-serializing can change floating point lexemes used by the gate or its digest.
    output.write(prefix)
    output.write(body)
    output.write(suffix)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument(
        "--analyzed-at", required=True, help="the scan's stable UTC timestamp"
    )
    args = parser.parse_args()
    try:
        write_envelope(
            args.report, args.branch, args.commit, args.analyzed_at, sys.stdout.buffer
        )
    except (OSError, ValueError) as exc:
        parser.exit(2, f"Cannot prepare analysis upload: {exc}\n")


if __name__ == "__main__":
    main()
