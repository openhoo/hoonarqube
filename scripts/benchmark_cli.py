#!/usr/bin/env python3
"""Compare two Linux CLI builds on identical inputs, including output parity.

Manual benchmark; never run in hosted CI. Both binaries use the same working
directory and CPU affinity. Run after builds/tests finish to avoid contention.
Only Python's standard library is required. Peak RSS comes from wait4 for each
child, not the cumulative resource usage of earlier benchmark runs.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time


def positive(value):
    """Parse a strictly positive run or CPU count."""
    count = int(value)
    if count < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return count


def digest(path):
    """Hash an artifact without loading its bytes into memory."""
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def measure(command, cwd, cpus, directory):
    """Capture one successful run with independent RSS and output evidence."""
    output = directory / "stdout"
    errors = directory / "stderr"
    with output.open("wb") as stdout, errors.open("wb") as stderr:
        previous_affinity = os.sched_getaffinity(0)
        os.sched_setaffinity(0, cpus)
        started = time.perf_counter()
        try:
            # Inherit affinity without executing Python in the child. This
            # allows subprocess to use vfork and avoids carrying the parent's
            # parsed-report heap through a preexec_fn into child RSS accounting.
            process = subprocess.Popen(command, cwd=cwd, stdout=stdout, stderr=stderr)
        finally:
            os.sched_setaffinity(0, previous_affinity)
        _, status, usage = os.wait4(process.pid, 0)
        elapsed = time.perf_counter() - started
        process.returncode = os.waitstatus_to_exitcode(status)
    if process.returncode != 0:
        raise RuntimeError(
            f"{command[0]} exited {process.returncode}: "
            f"{errors.read_text(errors='replace')[:2000]}"
        )
    # The CLI promises one complete JSON document. Check this outside timing.
    with output.open("rb") as stream:
        json.load(stream)
    return {
        "seconds": elapsed,
        "cpu_seconds": usage.ru_utime + usage.ru_stime,
        "peak_rss_kib": usage.ru_maxrss,
        "stdout_sha256": digest(output),
        "stderr_sha256": digest(errors),
        "output_bytes": output.stat().st_size,
    }


def main():
    """Alternate both builds and reject any output or warning differences."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", required=True, type=Path)
    parser.add_argument("--after", required=True, type=Path)
    parser.add_argument("--cwd", type=Path, default=Path.cwd())
    parser.add_argument("--runs", type=positive, default=5)
    parser.add_argument("--cpus", type=positive, default=1)
    parser.add_argument("--profile", default="sonar-parity")
    parser.add_argument("--format", choices=["json", "sonar", "sarif"], default="json")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("CPU affinity and RSS units require Linux")
    allowed = sorted(os.sched_getaffinity(0))
    if args.cpus > len(allowed):
        parser.error(f"only {len(allowed)} CPUs available in current affinity")
    cpus = allowed[: args.cpus]
    binaries = {"before": args.before.resolve(), "after": args.after.resolve()}
    arguments = [
        "analyze",
        "--profile",
        args.profile,
        "--format",
        args.format,
        "--",
        *args.paths,
    ]
    samples = {name: [] for name in binaries}
    signatures = set()
    with tempfile.TemporaryDirectory(prefix="hoonarqube-benchmark-") as temporary:
        directory = Path(temporary)
        # Warm both builds, then alternate order to reduce systematic drift.
        for iteration in range(args.runs + 1):
            order = list(binaries) if iteration % 2 == 0 else list(reversed(binaries))
            for name in order:
                sample = measure(
                    [str(binaries[name]), *arguments], args.cwd, cpus, directory
                )
                signatures.add((sample["stdout_sha256"], sample["stderr_sha256"]))
                if iteration:
                    samples[name].append(sample)
    summaries = {
        name: {
            "median_seconds": statistics.median(row["seconds"] for row in rows),
            "median_cpu_seconds": statistics.median(row["cpu_seconds"] for row in rows),
            "median_peak_rss_kib": statistics.median(
                row["peak_rss_kib"] for row in rows
            ),
            "max_peak_rss_kib": max(row["peak_rss_kib"] for row in rows),
            "binary_bytes": binaries[name].stat().st_size,
            "binary_sha256": digest(binaries[name]),
        }
        for name, rows in samples.items()
    }
    identical = len(signatures) == 1
    result = {
        "cwd": str(args.cwd.resolve()),
        "arguments": arguments,
        "cpus": cpus,
        "runs": args.runs,
        "output_identical": identical,
        "summaries": summaries,
        "samples": samples,
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output_identical": identical, **summaries}, indent=2))
    if not identical:
        raise SystemExit("output or warnings differ; inspect binaries on this corpus")


if __name__ == "__main__":
    main()
