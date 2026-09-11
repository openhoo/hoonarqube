#!/usr/bin/env python3
"""Compare two Linux CLI builds on identical inputs, including output parity.

Manual benchmark; never run in hosted CI. Both binaries use the same working
directory and CPU affinity. Run after builds/tests finish to avoid contention.
Only Python 3.11+'s standard library is required. Every pair is run in both
orders, with bounded timeout cleanup and input/binary immutability checks.
Reported RSS is the inner CLI's wait4 high-water only when above the fresh
supervisor's post-spawn VmHWM floor; unavailable values remain null.
"""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import threading
import signal
import stat
import statistics
import subprocess
import sys
import tempfile
import time


JSON_FORMATS = frozenset({"json", "sonar", "sarif", "gitlab-codequality"})
TERMINATION_GRACE_SECONDS = 1.0


def positive(value):
    """Parse a strictly positive run or CPU count."""
    try:
        count = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if count < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return count


def even_positive(value):
    """Parse a positive count that balances both alternating orders."""
    count = positive(value)
    if count % 2:
        raise argparse.ArgumentTypeError("must be even for balanced ordering")
    return count


def timeout_seconds(value):
    """Parse a finite, strictly positive timeout in seconds."""
    try:
        seconds = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number") from error
    if not math.isfinite(seconds) or seconds <= 0:
        raise argparse.ArgumentTypeError("must be finite and positive")
    return seconds


def digest(path):
    """Hash an artifact without loading its bytes into memory."""
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def safe_digest(path):
    """Return an artifact digest, or None when it disappeared/unreadable."""
    try:
        return digest(path)
    except (OSError, ValueError):
        return None


def _manifest_part(hasher, label, value):
    """Add one length-delimited byte field to an input manifest."""
    if isinstance(value, str):
        value = os.fsencode(value)
    hasher.update(label)
    hasher.update(len(value).to_bytes(8, "big"))
    hasher.update(value)


def _manifest_error(hasher, label, error):
    """Record an input traversal error instead of silently ignoring it."""
    _manifest_part(
        hasher,
        label,
        f"{type(error).__name__}:{getattr(error, 'errno', None)}".encode(),
    )


def _manifest_file(hasher, path):
    """Hash a regular input file into the manifest."""
    content = hashlib.sha256()
    try:
        with open(path, "rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                content.update(chunk)
    except (OSError, ValueError) as error:
        _manifest_error(hasher, b"content-error", error)
        return
    _manifest_part(hasher, b"content", content.digest())


def _manifest_directory(hasher, path, label, active_directories):
    """Recursively record a directory with byte-sorted, cycle-safe entries."""
    try:
        directory_stat = os.stat(path)
    except (OSError, ValueError) as error:
        _manifest_error(hasher, b"directory-error", error)
        return
    identity = (directory_stat.st_dev, directory_stat.st_ino)
    if identity in active_directories:
        _manifest_part(hasher, b"directory-cycle", b"")
        return
    active_directories.add(identity)
    try:
        try:
            with os.scandir(path) as scan:
                entries = sorted(scan, key=lambda entry: os.fsencode(entry.name))
        except (OSError, ValueError) as error:
            _manifest_error(hasher, b"scan-error", error)
            return
        for entry in entries:
            child_label = label + b"/" + os.fsencode(entry.name)
            _manifest_entry(hasher, entry.path, child_label, active_directories)
    finally:
        active_directories.remove(identity)


def _manifest_entry(hasher, path, label, active_directories):
    """Record one input path, including metadata and regular-file bytes."""
    _manifest_part(hasher, b"path", label)
    try:
        path_stat = os.lstat(path)
    except (OSError, ValueError) as error:
        _manifest_part(hasher, b"type", b"missing")
        _manifest_error(hasher, b"stat-error", error)
        return
    _manifest_part(hasher, b"type", str(stat.S_IFMT(path_stat.st_mode)).encode())
    _manifest_part(hasher, b"mode", str(path_stat.st_mode & 0o7777).encode())
    _manifest_part(hasher, b"size", str(path_stat.st_size).encode())
    _manifest_part(hasher, b"mtime-ns", str(path_stat.st_mtime_ns).encode())
    if stat.S_ISLNK(path_stat.st_mode):
        try:
            _manifest_part(hasher, b"link", os.fsencode(os.readlink(path)))
            followed_stat = os.stat(path)
        except (OSError, ValueError) as error:
            _manifest_error(hasher, b"link-error", error)
            return
        if stat.S_ISDIR(followed_stat.st_mode):
            _manifest_directory(hasher, path, label, active_directories)
        elif stat.S_ISREG(followed_stat.st_mode):
            _manifest_file(hasher, path)
    elif stat.S_ISDIR(path_stat.st_mode):
        _manifest_directory(hasher, path, label, active_directories)
    elif stat.S_ISREG(path_stat.st_mode):
        _manifest_file(hasher, path)


def input_fingerprint(cwd, paths):
    """Return a deterministic fingerprint of every analyzed path."""
    hasher = hashlib.sha256()
    cwd_bytes = os.fsencode(cwd)
    for index, raw_path in enumerate(paths):
        argument = os.fsencode(raw_path)
        _manifest_part(hasher, b"argument-index", str(index).encode())
        _manifest_part(hasher, b"argument", argument)
        candidate = (
            argument if os.path.isabs(argument) else os.path.join(cwd_bytes, argument)
        )
        _manifest_entry(
            hasher,
            os.path.normpath(candidate),
            f"input-{index}".encode(),
            set(),
        )
    return hasher.hexdigest()


_SUPERVISOR_CODE = r"""
import json
import os
import subprocess
import sys
import time


def _vmhwm_kib():
    try:
        with open("/proc/self/status", "rb") as stream:
            for line in stream:
                if line.startswith(b"VmHWM:"):
                    return int(line.split()[1])
    except (OSError, ValueError):
        return None
    return None


def _write(path, result):
    try:
        with open(path, "w", encoding="utf-8") as stream:
            json.dump(result, stream, sort_keys=True, separators=(",", ":"))
    except OSError:
        pass


metadata_path = sys.argv[1]
command = json.loads(sys.argv[2])
started = time.perf_counter()
try:
    child = subprocess.Popen(command)
except (OSError, ValueError) as error:
    _write(
        metadata_path,
        {"launch_error": f"{type(error).__name__}: {error}"},
    )
else:
    rss_floor_kib = _vmhwm_kib()
    while True:
        try:
            _, status, usage = os.wait4(child.pid, 0)
            break
        except InterruptedError:
            continue
    elapsed = time.perf_counter() - started
    exit_code = os.waitstatus_to_exitcode(status)
    child.returncode = exit_code
    _write(
        metadata_path,
        {
            "seconds": elapsed,
            "cpu_seconds": usage.ru_utime + usage.ru_stime,
            "raw_peak_rss_kib": usage.ru_maxrss,
            "rss_floor_kib": rss_floor_kib,
            "exit_code": exit_code,
        },
    )
"""


def _spawn(command, cwd, stdout, stderr, metadata):
    """Launch a fresh supervisor so wait4 cannot inherit this harness heap."""
    supervisor_command = [
        sys.executable,
        "-S",
        "-c",
        _SUPERVISOR_CODE,
        str(metadata),
        json.dumps([os.fsdecode(os.fspath(argument)) for argument in command]),
    ]
    return subprocess.Popen(
        supervisor_command,
        cwd=cwd,
        stdout=stdout,
        stderr=stderr,
        start_new_session=True,
    ), None


def _signal_group(pid, signum):
    """Signal the original process group, tolerating an already-empty group."""
    try:
        os.killpg(pid, signum)
    except ProcessLookupError:
        pass


def _sleep_uninterruptibly(seconds):
    """Complete timeout cleanup even when another SIGINT arrives."""
    deadline = time.monotonic() + seconds
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        try:
            time.sleep(remaining)
        except KeyboardInterrupt:
            continue


def _wait4_uninterruptibly(pid):
    """Reap a leader after process-group cleanup, ignoring cleanup interrupts."""
    while True:
        try:
            return os.wait4(pid, 0)
        except (InterruptedError, KeyboardInterrupt):
            continue


def _join_uninterruptibly(thread):
    """Join the watchdog even if SIGINT repeats during cleanup."""
    while thread.is_alive():
        try:
            thread.join()
        except KeyboardInterrupt:
            continue


def _waitid(pid):
    """Observe a leader exit without reaping it or masking SIGINT."""
    while True:
        try:
            return os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT)
        except InterruptedError:
            continue


def _wait4(pid):
    """Reap a normally completed leader, preserving KeyboardInterrupt."""
    while True:
        try:
            return os.wait4(pid, 0)
        except InterruptedError:
            continue


def _reap(process, timeout):
    """Retain the leader while a watchdog enforces and cleans its deadline."""
    leader_exited = threading.Event()
    abort = threading.Event()
    timed_out = threading.Event()

    def watchdog():
        if abort.wait(timeout):
            return
        timed_out.set()
        _signal_group(process.pid, signal.SIGTERM)
        # Keep the leader unreaped until the original process group has had
        # the full grace period. Escalate even when TERM killed the leader but
        # left a descendant alive in the same group.
        _sleep_uninterruptibly(TERMINATION_GRACE_SECONDS)
        _signal_group(process.pid, signal.SIGKILL)

    killer = threading.Thread(
        target=watchdog,
        name="hoonarqube-benchmark-timeout",
        daemon=True,
    )
    killer.start()
    try:
        _waitid(process.pid)
        leader_exited.set()
        abort.set()
        killer.join()
        _, status, usage = _wait4(process.pid)
    except BaseException:
        # Keep the leader unreaped while this path owns group cleanup. This
        # prevents PID/PGID reuse before the final SIGKILL and wait4, while
        # abort wakes a watchdog still waiting on the benchmark deadline.
        abort.set()
        leader_exited.set()
        _signal_group(process.pid, signal.SIGTERM)
        _sleep_uninterruptibly(TERMINATION_GRACE_SECONDS)
        _signal_group(process.pid, signal.SIGKILL)
        _join_uninterruptibly(killer)
        _, status, usage = _wait4_uninterruptibly(process.pid)
        process.returncode = os.waitstatus_to_exitcode(status)
        raise
    process.returncode = os.waitstatus_to_exitcode(status)
    return status, usage, timed_out.is_set()


def _preview(path, limit=2000):
    """Read a bounded diagnostic preview while hashing retains complete bytes."""
    try:
        with path.open("rb") as stream:
            content = stream.read(limit + 1)
    except OSError as error:
        return f"<unreadable stderr: {error}>", False
    truncated = len(content) > limit
    return content[:limit].decode("utf-8", errors="replace"), truncated


def _reject_json_constant(value):
    raise ValueError(f"non-standard JSON constant {value}")


def _validate_output(path, output_format):
    """Validate one complete JSON document for machine-readable formats."""
    if output_format not in JSON_FORMATS:
        return True, None
    try:
        with path.open("rb") as stream:
            json.load(stream, parse_constant=_reject_json_constant)
    except (OSError, ValueError, UnicodeDecodeError, RecursionError) as error:
        return False, str(error)
    return True, None


def measure(command, cwd, cpus, directory, output_format, timeout):
    """Capture one run, including failures, timeout, RSS, and output evidence."""
    directory.mkdir(parents=True)
    output = directory / "stdout"
    errors = directory / "stderr"
    metadata = directory / "supervisor.json"
    process = None
    launch_error = None
    timed_out = False
    status = None
    started = time.perf_counter()
    with output.open("wb") as stdout, errors.open("wb") as stderr:
        previous_affinity = os.sched_getaffinity(0)
        try:
            try:
                os.sched_setaffinity(0, cpus)
            except OSError as error:
                launch_error = f"{type(error).__name__}: {error}"
            if launch_error is None:
                try:
                    process, launch_error = _spawn(
                        command,
                        cwd,
                        stdout,
                        stderr,
                        metadata,
                    )
                except (OSError, TypeError, ValueError) as error:
                    launch_error = f"{type(error).__name__}: {error}"
        finally:
            try:
                os.sched_setaffinity(0, previous_affinity)
            except OSError as error:
                launch_error = f"{type(error).__name__}: {error}"
        if process is not None:
            status, _, timed_out = _reap(process, timeout)
    outer_elapsed = time.perf_counter() - started
    outer_exit_code = os.waitstatus_to_exitcode(status) if status is not None else None
    elapsed = outer_elapsed
    cpu_seconds = None
    raw_peak_rss_kib = None
    rss_floor_kib = None
    peak_rss_kib = None
    exit_code = outer_exit_code
    if process is not None and not timed_out:
        try:
            with metadata.open("r", encoding="utf-8") as stream:
                details = json.load(stream)
            if not isinstance(details, dict):
                raise ValueError("supervisor metadata is not an object")
            if "launch_error" in details:
                launch_error = str(details["launch_error"])
                exit_code = None
            else:
                elapsed = float(details["seconds"])
                cpu_seconds = float(details["cpu_seconds"])
                raw_peak_rss_kib = details["raw_peak_rss_kib"]
                rss_floor_kib = details["rss_floor_kib"]
                exit_code = details["exit_code"]
                if not isinstance(exit_code, int) or isinstance(exit_code, bool):
                    raise ValueError("supervisor exit code is not an integer")
                if (
                    isinstance(raw_peak_rss_kib, int)
                    and not isinstance(raw_peak_rss_kib, bool)
                    and isinstance(rss_floor_kib, int)
                    and not isinstance(rss_floor_kib, bool)
                    and raw_peak_rss_kib > rss_floor_kib
                ):
                    peak_rss_kib = raw_peak_rss_kib
        except (
            OSError,
            TypeError,
            ValueError,
            UnicodeDecodeError,
            RecursionError,
        ) as error:
            if launch_error is None:
                launch_error = f"supervisor metadata: {type(error).__name__}: {error}"
            exit_code = None
            elapsed = outer_elapsed
            cpu_seconds = None
            raw_peak_rss_kib = None
            rss_floor_kib = None
            peak_rss_kib = None
    output_valid = None
    output_error = None
    if exit_code == 0 and not timed_out:
        output_valid, output_error = _validate_output(output, output_format)
    stderr_preview, stderr_truncated = _preview(errors)
    returncode_signal = -exit_code if exit_code is not None and exit_code < 0 else None
    successful = (
        launch_error is None
        and exit_code == 0
        and not timed_out
        and output_valid is True
    )
    return {
        "command": command,
        "seconds": elapsed,
        "cpu_seconds": cpu_seconds,
        "peak_rss_kib": peak_rss_kib,
        "raw_peak_rss_kib": raw_peak_rss_kib,
        "rss_floor_kib": rss_floor_kib,
        "exit_code": exit_code,
        "signal": returncode_signal,
        "timed_out": timed_out,
        "launch_error": launch_error,
        "successful": successful,
        "output_valid": output_valid,
        "output_error": output_error,
        "stdout_sha256": digest(output),
        "stderr_sha256": digest(errors),
        "stdout_bytes": output.stat().st_size,
        "stderr_bytes": errors.stat().st_size,
        "stderr_preview": stderr_preview,
        "stderr_preview_truncated": stderr_truncated,
    }


def _path_from_cwd(cwd, raw_path):
    """Resolve one CLI path for output/input ownership checks."""
    path = Path(raw_path)
    return (cwd / path if not path.is_absolute() else path).resolve()


def _inside(path, parent):
    """Return whether path is parent or one of its descendants."""
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _outcome_signature(sample):
    """Normalize process outcomes for before/after exit equivalence."""
    return (
        sample["launch_error"] is None,
        sample["timed_out"],
        sample["exit_code"],
        sample["signal"],
    )


def _output_signature(sample):
    """Identify complete stdout/stderr byte streams without truncation."""
    return (
        sample["stdout_sha256"],
        sample["stdout_bytes"],
        sample["stderr_sha256"],
        sample["stderr_bytes"],
    )


def _valid_sample(sample, initial_input):
    """Select only successful runs on the unchanged benchmark input."""
    return (
        sample["successful"]
        and sample["input_sha256_before"] == initial_input
        and sample["input_sha256_after"] == initial_input
        and sample["input_unchanged"]
    )


def _summary(rows, binary, binary_before, binary_after, initial_input):
    """Summarize valid measured rows while retaining failure counts."""
    valid = [row for row in rows if _valid_sample(row, initial_input)]
    rss_values = [
        row["peak_rss_kib"] for row in valid if row["peak_rss_kib"] is not None
    ]

    def median(field):
        values = [row[field] for row in valid if row[field] is not None]
        return statistics.median(values) if values else None

    return {
        "median_seconds": median("seconds"),
        "median_cpu_seconds": median("cpu_seconds"),
        "median_peak_rss_kib": (statistics.median(rss_values) if rss_values else None),
        "max_peak_rss_kib": max(rss_values) if rss_values else None,
        "rss_samples": len(rss_values),
        "successful_runs": len(valid),
        "attempted_runs": len(rows),
        "binary_bytes": binary.stat().st_size if binary.is_file() else None,
        "binary_sha256_before": binary_before,
        "binary_sha256": binary_after,
        "binary_unchanged": binary_after == binary_before,
    }


def main():
    """Alternate both builds and reject failures or any output difference."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", required=True, type=Path)
    parser.add_argument("--after", required=True, type=Path)
    parser.add_argument("--cwd", type=Path, default=Path.cwd())
    parser.add_argument(
        "--runs",
        type=even_positive,
        default=6,
        help="measured runs per binary; even counts balance AB and BA pairs",
    )
    parser.add_argument(
        "--warmups",
        type=even_positive,
        default=2,
        help="unmeasured warmups per binary; even counts balance AB and BA pairs",
    )
    parser.add_argument("--timeout", type=timeout_seconds, default=300.0)
    parser.add_argument(
        "--cpus",
        type=positive,
        default=None,
        help="number of CPUs from the current affinity; omit to keep all allowed CPUs",
    )
    parser.add_argument(
        "--profile",
        choices=[
            "sonar-parity",
            "recommended",
            "extended",
            "strict",
            "github-code-quality",
        ],
        default="sonar-parity",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "sonar", "gitlab-codequality", "sarif"],
        default="json",
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("CPU affinity and RSS units require Linux")
    try:
        cwd = args.cwd.resolve()
    except (OSError, RuntimeError) as error:
        parser.error(f"cannot resolve --cwd: {error}")
    if not cwd.is_dir():
        parser.error(f"--cwd is not a directory: {cwd}")
    allowed = sorted(os.sched_getaffinity(0))
    if not allowed:
        parser.error("current process has no allowed CPUs")
    if args.cpus is None:
        cpus = allowed
    else:
        if args.cpus > len(allowed):
            parser.error(f"only {len(allowed)} CPUs available in current affinity")
        cpus = allowed[: args.cpus]
    try:
        binaries = {"before": args.before.resolve(), "after": args.after.resolve()}
    except (OSError, RuntimeError) as error:
        parser.error(f"cannot resolve benchmark binary: {error}")
    if binaries["before"] == binaries["after"]:
        parser.error("--before and --after must be different binaries")
    for name, binary in binaries.items():
        if not binary.is_file():
            parser.error(f"{name} binary is not a file: {binary}")
        if not os.access(binary, os.X_OK):
            parser.error(f"{name} binary is not executable: {binary}")
    try:
        raw_output = args.output
        if raw_output.exists() or raw_output.is_symlink():
            parser.error(
                "--output must be a new path (refusing to overwrite an existing file)"
            )
        output = raw_output.resolve()
        input_roots = [_path_from_cwd(cwd, raw_path) for raw_path in args.paths]
    except (OSError, RuntimeError, ValueError) as error:
        parser.error(f"cannot resolve benchmark paths: {error}")
    if any(_inside(output, root) for root in input_roots):
        parser.error("--output must not be inside an analyzed input path")
    if output.exists() or output.is_symlink():
        parser.error(
            "--output must be a new path (refusing to overwrite an existing file)"
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    binary_before = {name: digest(binary) for name, binary in binaries.items()}
    initial_input = input_fingerprint(cwd, args.paths)
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
    warmups = {name: [] for name in binaries}
    comparisons = []
    all_rows = []
    with tempfile.TemporaryDirectory(prefix="hoonarqube-benchmark-") as temporary:
        directory = Path(temporary)
        pair_number = 0

        def run_pair(collection, phase, iteration):
            nonlocal pair_number
            order = ["before", "after"] if pair_number % 2 == 0 else ["after", "before"]
            pair_number += 1
            pair_rows = {}
            for name in order:
                before_input = input_fingerprint(cwd, args.paths)
                sample = measure(
                    [str(binaries[name]), *arguments],
                    cwd,
                    cpus,
                    directory / f"{phase}-{iteration:03d}-{name}",
                    args.format,
                    args.timeout,
                )
                after_input = input_fingerprint(cwd, args.paths)
                sample.update(
                    {
                        "phase": phase,
                        "iteration": iteration,
                        "input_sha256_before": before_input,
                        "input_sha256_after": after_input,
                        "input_unchanged": before_input == after_input,
                    }
                )
                collection[name].append(sample)
                all_rows.append(sample)
                pair_rows[name] = sample
            before_row = pair_rows["before"]
            after_row = pair_rows["after"]
            comparisons.append(
                {
                    "phase": phase,
                    "iteration": iteration,
                    "order": order,
                    "exit_equivalent": _outcome_signature(before_row)
                    == _outcome_signature(after_row),
                    "output_identical": _output_signature(before_row)
                    == _output_signature(after_row),
                }
            )

        for iteration in range(args.warmups):
            run_pair(warmups, "warmup", iteration)
        for iteration in range(args.runs):
            run_pair(samples, "measured", iteration)
    binary_after = {name: safe_digest(binary) for name, binary in binaries.items()}
    summaries = {
        name: _summary(
            rows,
            binaries[name],
            binary_before[name],
            binary_after[name],
            initial_input,
        )
        for name, rows in samples.items()
    }
    output_signatures = {_output_signature(row) for row in all_rows}
    output_identical = bool(all_rows) and len(output_signatures) == 1
    exit_equivalent = bool(comparisons) and all(
        comparison["exit_equivalent"] for comparison in comparisons
    )
    complete_outputs = bool(all_rows) and all(
        row["output_valid"] is True for row in all_rows
    )
    commands_succeeded = bool(all_rows) and all(row["successful"] for row in all_rows)
    inputs_unchanged = bool(all_rows) and all(
        row["input_unchanged"]
        and row["input_sha256_before"] == initial_input
        and row["input_sha256_after"] == initial_input
        for row in all_rows
    )
    binaries_unchanged = all(
        binary_after[name] == binary_before[name] for name in binaries
    )
    failures = []
    if not commands_succeeded:
        failures.append("a command failed or timed out")
    if not complete_outputs:
        failures.append(
            "one or more outputs were not complete machine-readable documents"
        )
    if not output_identical:
        failures.append("stdout/stderr bytes differ or are nondeterministic")
    if not exit_equivalent:
        failures.append("before/after exit outcomes differ")
    if not inputs_unchanged:
        failures.append("analyzed inputs changed during the benchmark")
    if not binaries_unchanged:
        failures.append("a benchmark binary changed during the benchmark")
    valid = not failures
    result = {
        "valid": valid,
        "cwd": str(cwd),
        "arguments": arguments,
        "profile": args.profile,
        "format": args.format,
        "cpus": cpus,
        "runs": args.runs,
        "warmups": args.warmups,
        "timeout_seconds": args.timeout,
        "initial_input_sha256": initial_input,
        "binary_sha256_before": binary_before,
        "binary_sha256_after": binary_after,
        "output_identical": output_identical,
        "exit_equivalent": exit_equivalent,
        "complete_outputs": complete_outputs,
        "commands_succeeded": commands_succeeded,
        "inputs_unchanged": inputs_unchanged,
        "binaries_unchanged": binaries_unchanged,
        "comparisons": comparisons,
        "summaries": summaries,
        "warmup_samples": warmups,
        "samples": samples,
    }
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "valid": valid,
                "output_identical": output_identical,
                "exit_equivalent": exit_equivalent,
                "complete_outputs": complete_outputs,
                "commands_succeeded": commands_succeeded,
                "summaries": summaries,
            },
            indent=2,
        )
    )
    if failures:
        raise SystemExit("benchmark invalid: " + "; ".join(failures))


if __name__ == "__main__":
    main()
