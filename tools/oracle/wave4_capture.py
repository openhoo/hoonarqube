#!/usr/bin/env python3
"""Run native and independent SonarQube captures of the Wave 4 source pins."""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import subprocess
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError

import public_corpus_capture as capture
import public_corpus_summary as comparison
import public_corpus_wave2_capture as profiles
from parity import read_json, write_json_atomic
from public_corpus_wave3_replay import verify_profiles, verify_reference_environment
from wave4_build_receipt import verify_receipt
from wave4_prepare import (
    EXTENSIONS,
    PREFIX,
    REPO,
    SHA,
    historical_identity,
    require_disk,
    verify_sparse_checkout,
)

WAVE3 = Path(__file__).with_name("public-corpus-wave3-qualification-20261120.json")
COUNTS = ("matched", "native_only", "reference_only")
SENSORS = {
    "go": "Sensor Code Quality and Security for Go [go]",
    "py": "Sensor Python Sensor [python]",
    "ruby": "Sensor Ruby Sensor [ruby]",
    "js": "Sensor JavaScript/TypeScript/CSS analysis [javascript]",
    "ts": "Sensor JavaScript/TypeScript/CSS analysis [javascript]",
    "rust": "Sensor Rust [rust]",
}


def rows_for(state: Path) -> list[dict]:
    rows = read_json(state / "prepared.json")
    known = historical_identity()
    keys = set()
    for row in rows:
        name = row["name"]
        if (
            not re.fullmatch(r"[a-z0-9-]+", name)
            or row["project_key"] != PREFIX + name
            or row["language"] not in EXTENSIONS
            or row["path"] != str(state / "sources" / name)
            or row["sources"] != sorted(row["source_inventory"])
            or name in keys
        ):
            raise ValueError(f"invalid prepared source: {name}")
        keys.add(name)
        for key in known:
            value = row[key].casefold()
            if value in known[key]:
                raise ValueError(f"{name}: repeated {key} from prior qualification")
            known[key].add(value)
            if key in {"commit", "tree"} and not SHA.fullmatch(value):
                raise ValueError(f"{name}: invalid {key}")
    return rows


def verify_analysis_task(folder: Path, project_key: str) -> dict:
    task = read_json(folder / "compute-engine.json")["task"]
    if (
        task.get("status") != "SUCCESS"
        or task.get("componentKey") != project_key
        or not task.get("id")
        or not task.get("analysisId")
    ):
        raise ValueError("compute-engine task does not prove a fresh project analysis")
    return task


def archive_generated_helpers(row, root, folder):
    helpers = tuple(profiles.helper_paths(row, root))
    profiles.archive_generated_helpers(row, root, folder)
    for helper in helpers:
        # Git does not track empty directories; restore the sparse worktree
        # after archiving the verified helper and its private cache path.
        for directory in helper.parents[:3]:
            if any(directory.iterdir()):
                break
            directory.rmdir()


def require_fresh_project(sonar, project_key):
    try:
        sonar.request("/api/components/show", {"component": project_key})
    except HTTPError as error:
        if error.code != 404:
            raise
    else:
        raise ValueError("reference project is not fresh")


def capture_one(row, args, phase, output, sonar=None, token=""):
    started = capture.utc()
    folder = output / row["name"]
    progress = folder / "progress.json"
    if progress.is_file() and (result := read_json(progress)).get("ended_at_utc"):
        if row != read_json(folder / "source.json"):
            raise ValueError("existing capture belongs to a different source pin")
        return result[phase]["status"]
    if folder.exists():
        raise ValueError(f"interrupted raw capture already exists: {folder}")
    try:
        require_disk(args.state)
        if phase == "reference":
            require_fresh_project(sonar, row["project_key"])
        result = capture.execute(
            row,
            SimpleNamespace(
                state=args.state,
                output=output,
                binary=args.binary,
                reference_only=phase == "reference",
                native_only=phase == "native",
                no_shared_cache=phase == "native",
            ),
            sonar,
            token,
            checkout_verifier=verify_sparse_checkout,
            helper_handler=archive_generated_helpers,
        )
        if phase == "reference" and result[phase]["status"] == "complete":
            verify_analysis_task(folder, row["project_key"])
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        folder.mkdir(exist_ok=True)
        if progress.is_file():
            write_json_atomic(
                folder / "progress-before-postcheck.json", read_json(progress)
            )
        write_json_atomic(folder / "source.json", row)
        result = {
            "started_at_utc": started,
            "ended_at_utc": capture.utc(),
            "reference": {"status": "not_run"},
            "native": {"status": "not_run"},
        }
        result[phase] = {"status": "failed", "reason": str(error)}
        write_json_atomic(progress, result)
    disposition = result[phase]["status"]
    print(phase, row["name"], disposition, result[phase].get("reason", ""), flush=True)
    return disposition


def phase_capture(rows, args, phase, sonar=None, token=""):
    output = args.state / phase
    output.mkdir(exist_ok=True)
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = [
            pool.submit(capture_one, row, args, phase, output, sonar, token)
            for row in rows
        ]
        return Counter(future.result() for future in as_completed(futures))


def native(args, rows):
    if not args.binary or not args.build_receipt:
        raise ValueError("native requires --binary and --build-receipt")
    args.binary = args.binary.resolve(strict=True)
    build = read_json(args.build_receipt)
    commit = subprocess.check_output(
        ["git", "-C", str(REPO), "rev-parse", "HEAD"], text=True
    ).strip()
    verify_receipt(REPO, build, binary=args.binary, expected_commit=commit)
    build["version"] = subprocess.check_output(
        [str(args.binary), "--version"], text=True, timeout=10
    ).strip()
    provenance = args.state / "native-build.json"
    if provenance.is_file() and read_json(provenance) != build:
        raise ValueError("recorded native build changed; use a new state directory")
    write_json_atomic(provenance, build)
    catalog = subprocess.check_output(
        [str(args.binary), "rules", "list", "--json"], text=True, timeout=45
    )
    (args.state / "native-catalog.json").write_text(catalog)
    return phase_capture(rows, args, "native")


def validate_reference_configuration(details, network, container_id, network_name):
    host = details["HostConfig"]
    if (
        not container_id
        or details["Id"] != container_id
        or details["Config"]["Image"] != capture.SERVER_IMAGE
        or set(details["NetworkSettings"]["Networks"]) != {network_name}
        or network["Internal"] is not True
        or host.get("Privileged")
        or host.get("PortBindings")
        or host.get("PublishAllPorts")
    ):
        raise ValueError("reference is not the pinned, private Community container")


def expected_reference() -> dict:
    return read_json(WAVE3)["provenance"]["reference"]


def verify_environment(observed: dict) -> None:
    expected = expected_reference()
    if observed["server"]["status"] != "UP":
        raise ValueError("reference SonarQube is not ready")
    for key, architectures in (
        ("server_image", {"arm64", "amd64"}),
        ("scanner_image", {"amd64"}),
    ):
        image = observed[key]
        architecture, operating_system, _ = image["platform_fingerprint"].split()
        if (
            image["image"] != expected[key]["image"]
            or operating_system != "linux"
            or architecture not in architectures
        ):
            raise ValueError(
                "reference image fingerprint differs from the pinned platform"
            )
    # Check the exact same installed analyzer artifacts across platforms.
    aligned = {
        **observed,
        **{k: expected[k] for k in ("server_image", "scanner_image")},
    }
    verify_reference_environment(aligned, expected)


def attach_reference(args):
    if not (
        args.docker_state
        and all(
            re.fullmatch(r"[a-z0-9][a-z0-9_.-]+", value or "")
            for value in (args.server, args.network, args.cache)
        )
    ):
        raise ValueError(
            "reference requires --server, --network, --cache and --docker-state"
        )
    config = subprocess.check_output(["docker", "context", "inspect"], timeout=10)
    endpoint = (
        os.environ.get("DOCKER_HOST") if not os.environ.get("DOCKER_CONTEXT") else None
    ) or json.loads(config)[0]["Endpoints"]["docker"]["Host"]
    if not endpoint.startswith("unix:///"):
        raise ValueError("reference capture requires a local Docker socket")
    subprocess.run(
        ["docker", "version", "--format", "{{.Server.Version}}"], check=True, timeout=10
    )
    capture.SERVER, capture.NETWORK, capture.CACHE = (
        args.server,
        args.network,
        args.cache,
    )
    details = json.loads(
        subprocess.check_output(["docker", "inspect", args.server], timeout=10)
    )[0]
    network = json.loads(
        subprocess.check_output(
            ["docker", "network", "inspect", args.network], timeout=10
        )
    )[0]
    validate_reference_configuration(
        details,
        network,
        (args.docker_state / "docker/server.id").read_text().strip(),
        args.network,
    )
    password_path = args.docker_state / "local-admin-password"
    if (
        not password_path.exists()
        and not (args.docker_state / "local-reference-token").exists()
    ):
        password = secrets.token_urlsafe(40) + "Aa4!"
        capture.DockerSonar("admin:admin").request(
            "/api/users/change_password",
            {"login": "admin", "previousPassword": "admin", "password": password},
            post=True,
        )
        password_path.write_text(password + "\n")
    token = capture.bootstrap(args.docker_state)
    live = capture.DockerSonar(token + ":")
    observed = capture.reference_environment(live)
    verify_environment(observed)
    saved = args.state / "reference-environment.json"
    if saved.is_file() and (
        {k: v for k, v in observed.items() if k != "captured_at_utc"}
        != {k: v for k, v in read_json(saved).items() if k != "captured_at_utc"}
    ):
        raise ValueError("reference environment changed within the capture state")
    if not saved.is_file():
        write_json_atomic(saved, observed)
    return live, token


def reference(args, rows):
    live, token = attach_reference(args)
    pilot_row = rows[0]
    profiles.PILOT = pilot_row["name"]
    pilot = args.state / "pilot"
    pilot.mkdir(exist_ok=True)
    if capture_one(pilot_row, args, "reference", pilot, live, token) != "complete":
        raise ValueError("SonarQube reference pilot did not complete")
    if not (args.state / "profiles/effective.json").exists():
        profiles.capture_effective_profiles(args.state, live)
    verify_profiles(args.state / "profiles", expected_reference())
    frozen = profiles.FrozenProfileSonar(token + ":", pilot / pilot_row["name"])
    counts = phase_capture(rows[1:], args, "reference", frozen, token)
    counts["complete"] += 1
    if not (args.state / "profiles-end/effective.json").exists():
        profiles.capture_effective_profiles(args.state, live, refresh=True)
    verify_profiles(args.state / "profiles-end", expected_reference())
    return counts


def reference_scope(log: str, language: str, files: int) -> dict:
    sensor = re.escape(SENSORS[language])
    blocks = re.findall(
        rf"{sensor}$\n(.*?){sensor} \(done\)", log, re.MULTILINE | re.DOTALL
    )
    if not blocks and language == "go":
        # The Go plug-in's stable sensor name is present without this optional
        # build prefix in earlier scanner logs.
        blocks = re.findall(
            r"Sensor Go Sensor \[go\]$\n(.*?)Sensor Go Sensor \[go\] \(done\)",
            log,
            re.MULTILINE | re.DOTALL,
        )
    if len(blocks) != 1:
        return {"state": "missing_sensor_log"}
    readback = re.findall(
        r"\b(\d+)/(\d+) source files? (?:has|have) been analyzed\s*$",
        blocks[0],
        re.MULTILINE,
    )
    if language == "go":
        go_counts = re.findall(
            r"\b(\d+)/(\d+) folders? \((\d+) files?\) (?:has|have) been analyzed\s*$",
            blocks[0],
            re.MULTILINE,
        )
        if go_counts:
            dirs, all_dirs, processed = map(int, go_counts[-1])
            return {
                "state": "count_matches"
                if dirs == all_dirs and processed == files
                else "count_differs",
                "processed": processed,
                "folders_processed": dirs,
                "folders_total": all_dirs,
            }
    if not readback:
        return {"state": "completed_without_file_count"}
    processed, total = map(int, readback[-1])
    return {
        "state": "count_matches" if processed == total == files else "count_differs",
        "processed": processed,
        "sensor_total": total,
    }


def verified_profiles(state, reference_env):
    profile_start = state / "profiles/effective.json"
    profile_end = state / "profiles-end/effective.json"
    if reference_env is None or not (profile_start.exists() and profile_end.exists()):
        return None
    effective = read_json(profile_start)["profiles"]
    if effective != read_json(profile_end)["profiles"]:
        return None
    verify_environment(reference_env)
    verify_profiles(profile_start.parent, expected_reference())
    verify_profiles(profile_end.parent, expected_reference())
    return effective


def qualify_scope(record, ref_dir, result):
    num_files = record["files"]["shared"]
    observed = reference_scope(
        (ref_dir / "scanner.stdout").read_text(), result["language"], num_files
    )
    result["reference"]["sensor"] = observed
    if num_files != result["source_count"]:
        return "not_compared_short_of_pinned_scope"
    if observed["state"] in {"count_differs", "missing_sensor_log"}:
        return "not_compared_reference_sensor_scope"
    group = record["findings"]["shared_files"]["by_class"].get(
        "shared_equal_declared_parameters", {}
    )
    result.update(
        shared_files=num_files,
        primary={k: group.get(k, 0) for k in COUNTS},
        file_metric_cells=record["metrics"]["shared_file_metrics"],
    )
    return "same_scope"


def add_compute_task(ref_dir, project_key, reference):
    ce = ref_dir / "compute-engine.json"
    if ce.is_file():
        task = (
            verify_analysis_task(ref_dir, project_key)
            if reference["state"] == "complete"
            else read_json(ce)["task"]
        )
        reference.update(task_id=task.get("id"), analysis_id=task.get("analysisId"))


def summarize_row(state, row, reference_section, effective, catalog, infra):
    key = row["name"]
    native_dir = state / "native" / key
    ref_dir = state / reference_section / key
    if not (ref_dir / "progress.json").is_file():
        ref_dir = native_dir
    progress_path = native_dir / "progress.json"
    if not progress_path.is_file():
        raise ValueError(f"{key}: native capture is missing")
    result = {
        **{
            k: row[k]
            for k in ("repository", "commit", "tree", "language", "scope_root")
        },
        "source_count": len(row["sources"]),
        "source_inventory_sha256": comparison.canonical_sha(row["source_inventory"]),
    }
    record = (
        comparison.summarize_project(
            ref_dir,
            effective,
            catalog,
            infra,
            native_dir,
            checkout_verifier=verify_sparse_checkout,
        )
        if effective is not None
        else comparison.project_metadata(
            ref_dir, native_dir, checkout_verifier=verify_sparse_checkout
        )[1]
    )
    result.update({k: record[k] for k in ("native", "reference", "evidence_sha256")})
    if reason := read_json(progress_path)["native"].get("reason"):
        result["native"]["reason"] = reason
    if reason := read_json(ref_dir / "progress.json")["reference"].get("reason"):
        result["reference"]["reason"] = reason
    decision = record.get("comparison_state", "not_compared_no_verified_reference")
    identical_indexes = decision == "same_scope"
    if identical_indexes:
        decision = qualify_scope(record, ref_dir, result)
    if "files" in record and decision != "same_scope":
        result["file_scope"] = record["files"]
    add_compute_task(ref_dir, row["project_key"], result["reference"])
    result["comparison_state"] = decision
    return result, identical_indexes


def summarize(state, rows):
    native_build = read_json(state / "native-build.json")
    catalog = {
        row["external_key"]: row["rule_type"]
        for row in read_json(state / "native-catalog.json")
    }
    infra, boundary, _ = comparison.verified_boundaries(
        verify_receipt(REPO, native_build)
    )
    env_path = state / "reference-environment.json"
    reference_env = read_json(env_path) if env_path.exists() else None
    effective = verified_profiles(state, reference_env)
    normalized_profiles = {
        language: {k: v for k, v in data.items() if k != "profile_key"}
        for language, data in (effective or {}).items()
    }
    counts, metrics = Counter(), Counter()
    files, indexed, results = 0, 0, []
    for index, row in enumerate(rows):
        result, identical_indexes = summarize_row(
            state,
            row,
            "pilot" if index == 0 else "reference",
            effective,
            catalog,
            infra,
        )
        indexed += identical_indexes
        if result["comparison_state"] == "same_scope":
            files += result["shared_files"]
            counts.update(result["primary"])
            cells = result["file_metric_cells"]
            metrics.update({k: cells[k] for k in ("matched_cells", "compared_cells")})
        results.append(result)
    receipt = {
        "schema_version": 1,
        "created_at_utc": capture.utc(),
        "native": native_build,
        "native_boundary_sha256": boundary,
        "reference": reference_env,
        "reference_profiles_verified": effective is not None,
        "reference_profiles_sha256": comparison.canonical_sha(normalized_profiles)
        if effective is not None
        else None,
        "projects": results,
        "counts": {
            "projects": len(results),
            "native": dict(Counter(r["native"]["status"] for r in results)),
            "reference": dict(Counter(r["reference"]["state"] for r in results)),
            "states": dict(Counter(r["comparison_state"] for r in results)),
            "pairs_with_identical_indexes": indexed,
            "comparable_files": files,
            "comparable_primary": dict(counts),
            "file_metrics": dict(metrics),
        },
    }
    write_json_atomic(state / "wave4-receipt.json", receipt)
    return receipt["counts"]


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("native", "reference", "summary"))
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--build-receipt", type=Path)
    parser.add_argument("--server")
    parser.add_argument("--network")
    parser.add_argument("--cache")
    parser.add_argument("--docker-state", type=Path)
    parser.add_argument("--jobs", type=int, choices=[1, 2], default=1)
    args = parser.parse_args()
    args.state = args.state.resolve(strict=True)
    rows = rows_for(args.state)
    if args.phase == "native":
        result = native(args, rows)
    elif args.phase == "reference":
        result = reference(args, rows)
    else:
        result = summarize(args.state, rows)
    print(dict(result), flush=True)
    return 1 if args.phase == "reference" and result["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
