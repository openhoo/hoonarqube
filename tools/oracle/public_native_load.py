"""Time fresh macOS native scanner processes against a frozen corpus contract."""

import argparse
import csv
from contextlib import suppress
import json
import math
import os
from pathlib import Path
import platform
import signal
import statistics
import subprocess
import threading
import time
from datetime import UTC, datetime

from parity import read_json, write_json_atomic
from public_corpus_summary import canonical_sha
from public_go_pipeline import inventory
from real_project_suite import digest, verify_source


def now():
    return datetime.now(UTC).isoformat()


def checkout(root, name, row):
    target = verify_source({"path": root / name, "name": name, "commit": row["commit"]})
    tree = subprocess.check_output(
        ["git", "rev-parse", "HEAD^{tree}"], cwd=target, text=True
    )
    untracked = subprocess.check_output(
        ["git", "ls-files", "--others", "-z"], cwd=target
    )
    if tree.strip() != row["tree"] or untracked:
        raise ValueError(
            f"{name}: use a fresh checkout with no generated compiler context"
        )
    return target


def verify_report(report, root, row):
    doc = read_json(report)
    files = inventory(root, (f["path"] for f in doc["files"]))
    if not (
        doc["project"]["complete"]
        and doc["project"]["metrics"] == row["metrics"]
        and doc["parity"]["semantic_context"] == row["semantic_context"]
        and canonical_sha(files) == row["inventory_sha256"]
    ):
        raise ValueError("measured scope, compiler context, or source content differs")


def timed_scan(binary, args, cwd, folder, timeout):
    # Use posix_spawn so the scanner does not inherit a Python parent's RSS via fork.
    folder.mkdir()
    previous = Path.cwd()

    def expired(*_):
        raise TimeoutError("scanner timeout")

    handler = signal.signal(signal.SIGALRM, expired)
    try:
        os.chdir(cwd)
        with (
            (folder / "stdout").open("xb") as out,
            (folder / "stderr").open("xb") as err,
        ):
            actions = [
                (os.POSIX_SPAWN_DUP2, out.fileno(), 1),
                (os.POSIX_SPAWN_DUP2, err.fileno(), 2),
            ]
            started = time.perf_counter_ns()
            pid = os.posix_spawn(
                binary,
                [str(binary), *args],
                os.environ,
                file_actions=actions,
                setpgroup=0,
            )
            try:
                signal.alarm(timeout)
                _, status, usage = os.wait4(pid, 0)
            except BaseException:
                with suppress(ProcessLookupError):
                    os.killpg(pid, signal.SIGKILL)
                with suppress(ChildProcessError):
                    os.waitpid(pid, 0)
                raise
            finally:
                signal.alarm(0)
            elapsed = (time.perf_counter_ns() - started) / 1e9
    finally:
        signal.signal(signal.SIGALRM, handler)
        os.chdir(previous)
    if os.waitstatus_to_exitcode(status):
        raise ValueError(f"nonzero scanner exit: {folder}")
    return {
        "wall_s": elapsed,
        "user_s": usage.ru_utime,
        "system_s": usage.ru_stime,
        "wait4_maxrss_bytes": usage.ru_maxrss,
    }


def host_sample():
    # ps reports recent per-process CPU, in percentages of one logical CPU.
    raw = subprocess.check_output(["ps", "-axo", "pcpu=,comm="], text=True, cwd="/")
    other, builds, scanners = 0.0, 0.0, 0.0
    for line in raw.splitlines():
        fields = line.strip().split(maxsplit=1)
        if len(fields) != 2:
            continue
        cpu = float(fields[0])
        name = Path(fields[1]).name
        if name == "hoonarqube":
            scanners += cpu
        else:
            other += cpu
            if name in {
                "rustc",
                "cargo",
                "clang",
                "clang++",
                "javac",
                "tested-service",
                "hoonarqube-service",
            }:
                builds += cpu
    return {
        "at": now(),
        "background_cpu_pct": round(other, 2),
        "build_service_cpu_pct": round(builds, 2),
        "scanner_cpu_pct": round(scanners, 2),
        "load1": os.getloadavg()[0],
    }


def observe(stop, file, readings, errors):
    try:
        with file.open("x") as out:
            while not stop.is_set():
                snap = host_sample()
                readings.append(snap)
                out.write(json.dumps(snap) + "\n")
                out.flush()
                stop.wait(2)
    except Exception as exc:
        errors.append(repr(exc))


def percentiles(values):
    ordered = sorted(values)
    return {
        "min": min(ordered),
        "p50": statistics.median(ordered),
        "p95": ordered[math.ceil(0.95 * len(ordered)) - 1],
        "max": max(ordered),
    }


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", required=True, type=Path)
    parser.add_argument("--sources", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--contract",
        type=Path,
        default=Path(__file__).with_name("public-native-load-contract-20261120.json"),
    )
    parser.add_argument("--rounds", type=int, default=20)
    parser.add_argument("--warmups", type=int, default=2)
    args = parser.parse_args()
    if platform.system() != "Darwin" or args.rounds < 20 or args.warmups < 1:
        parser.error("macOS, at least 20 rounds and a separate warm-up are required")
    return args


def await_quiet_start(out):
    # Wait for three consecutive light observations; never discard individual samples.
    quiet = []
    for _ in range(90):
        snap = host_sample()
        quiet.append(snap)
        if len(quiet) >= 3 and all(
            x["build_service_cpu_pct"] < 25 and x["background_cpu_pct"] < 300
            for x in quiet[-3:]
        ):
            break
        time.sleep(2)
    else:
        write_json_atomic(out / "preflight-load.json", quiet)
        raise RuntimeError(
            "no low-contention start within three minutes; preserve this attempt and retry later"
        )
    write_json_atomic(out / "preflight-load.json", quiet)


def run_rotations(binary, projects, roots, out, args):
    names = list(projects)
    raw = []
    for r in range(-args.warmups, args.rounds):
        offset = r % len(names)
        for n in names[offset:] + names[:offset]:
            label = "warm" + str(-r) if r < 0 else f"round{r + 1:02}"
            row, folder = projects[n], out / f"{label}-{n}"
            snap = timed_scan(binary, row["argv"], roots[n], folder, 240)
            for channel in ["stdout", "stderr"]:
                if digest(folder / channel) != row[f"expected_{channel}_sha256"]:
                    raise ValueError(f"output changed: {n} {label} {channel}")
            if r in [-args.warmups, args.rounds - 1]:
                verify_report(folder / "stdout", roots[n], row)
            write_json_atomic(folder / "sample.json", snap)
            raw.append({"project": n, "round": r, **snap})
            print(label, n, round(snap["wall_s"], 3), flush=True)
    return raw


def measure(binary, projects, roots, out, args):
    stop = threading.Event()
    observations = []
    errors = []
    monitor = threading.Thread(
        target=observe,
        args=(stop, out / "host-load.jsonl", observations, errors),
        daemon=True,
    )
    monitor.start()
    try:
        raw = run_rotations(binary, projects, roots, out, args)
    finally:
        stop.set()
        monitor.join()
    if errors or not observations:
        raise RuntimeError(f"host sampling failed: {errors}")
    return raw, observations


def summarize(rows):
    return {k: percentiles([s[k] for s in rows]) for k in FIELDS}


FIELDS = ("wall_s", "user_s", "system_s", "wait4_maxrss_bytes")


def portable_outputs(out):
    """Export the observed samples without copying upstream source or scanner output."""
    raw = read_json(out / "samples.json")
    summary = read_json(out / "summary.json")
    if summary["raw_samples_sha256"] != digest(out / "samples.json") or summary[
        "load_samples_sha256"
    ] != digest(out / "host-load.jsonl"):
        raise ValueError("raw observation digest differs from the run receipt")
    with (out / "samples.csv").open("x", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["project", "round", *FIELDS], lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(raw)
    observations = [
        json.loads(line) for line in (out / "host-load.jsonl").read_text().splitlines()
    ]
    preflight = read_json(out / "preflight-load.json")
    summary["host"] = {
        "macos": platform.mac_ver()[0],
        "chip": subprocess.check_output(
            ["sysctl", "-n", "machdep.cpu.brand_string"], text=True
        ).strip(),
        "physical_memory_bytes": int(
            subprocess.check_output(["sysctl", "-n", "hw.memsize"])
        ),
        "first_probe_at_utc": observations[0]["at"],
        "last_probe_at_utc": observations[-1]["at"],
        "preflight_background_cpu_pct": [s["background_cpu_pct"] for s in preflight],
        "preflight_build_service_cpu_pct": [
            s["build_service_cpu_pct"] for s in preflight
        ],
        "build_service_at_least_25_pct": sum(
            s["build_service_cpu_pct"] >= 25 for s in observations
        ),
        "background_at_least_one_core": sum(
            s["background_cpu_pct"] >= 100 for s in observations
        ),
        "build_service_cpu_pct": percentiles(
            [s["build_service_cpu_pct"] for s in observations]
        ),
    }
    summary["samples_csv_sha256"] = digest(out / "samples.csv")
    write_json_atomic(out / "release-timing.json", summary, indent=2)


def main():
    args = parse_args()
    contract = read_json(args.contract)
    projects = contract["projects"]
    binary = args.native.resolve(strict=True)
    if digest(binary) != contract["release"]["binary_sha256"]:
        raise ValueError("binary bytes differ from the release receipt")
    root = args.sources.resolve(strict=True)
    out = args.output.resolve()
    out.mkdir(exist_ok=False)
    roots = {n: checkout(root, n, row) for n, row in projects.items()}
    start = now()
    await_quiet_start(out)
    raw, observations = measure(binary, projects, roots, out, args)
    for n, row in projects.items():
        checkout(root, n, row)
    if digest(binary) != contract["release"]["binary_sha256"]:
        raise ValueError("binary changed during timing")
    metrics = {
        n: summarize([s for s in raw if s["project"] == n and s["round"] >= 0])
        for n in projects
    }
    write_json_atomic(out / "samples.json", raw)
    summary = {
        "started_at_utc": start,
        "finished_at_utc": now(),
        "binary_sha256": digest(binary),
        "contract_sha256": digest(args.contract),
        "system": platform.system(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "logical_cpus": os.cpu_count(),
        "rounds": args.rounds,
        "warmups": args.warmups,
        "projects": metrics,
        "host_observations": len(observations),
        "host_background_cpu_pct": percentiles(
            [s["background_cpu_pct"] for s in observations]
        ),
        "build_service_at_least_one_core": sum(
            s["build_service_cpu_pct"] >= 100 for s in observations
        ),
        "raw_samples_sha256": digest(out / "samples.json"),
        "load_samples_sha256": digest(out / "host-load.jsonl"),
    }
    write_json_atomic(out / "summary.json", summary)
    portable_outputs(out)


if __name__ == "__main__":
    main()
