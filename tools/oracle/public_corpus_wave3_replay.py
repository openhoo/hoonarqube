#!/usr/bin/env python3
"""Replay the pinned third public corpus in a fresh private state directory."""

from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import subprocess
from types import SimpleNamespace
from urllib.error import HTTPError

import public_corpus_capture as capture
import public_corpus_summary as comparison
import public_corpus_wave2_capture as profiles
from public_corpus_wave2_prepare import checkout, require_disk
from parity import read_json, write_json_atomic

MANIFEST = Path(__file__).with_name("public-corpus-wave3-projects-20261120.json")
RECEIPT = Path(__file__).with_name("public-corpus-wave3-qualification-20261120.json")
PILOT = "httpx"
PREFIX = "hq-public-wave3-20261120-"


def load_manifest(path):
    manifest = read_json(path)
    rows = manifest["projects"]
    if (
        manifest["schema_version"] != 1
        or manifest["scope"] != "wave3"
        or len(rows) != 52
        or len({r["name"] for r in rows}) != len(rows)
        or len({r["repository"].casefold() for r in rows}) != len(rows)
        or PILOT not in {r["name"] for r in rows}
        or any(row["project_key"] != PREFIX + row["name"] for row in rows)
    ):
        raise ValueError("invalid Wave 3 manifest")
    for row in rows:
        if not re.fullmatch(r"[a-z0-9-]+", row["name"]):
            raise ValueError("unexpected project name in Wave 3 manifest")
        if not all(
            re.fullmatch(r"[0-9a-f]{40}", row[key]) for key in ("commit", "tree")
        ):
            raise ValueError(f"{row['name']}: incomplete commit or tree pin")
        if not row["sources"] or any(
            not source
            or PurePosixPath(source).is_absolute()
            or ".." in PurePosixPath(source).parts
            for source in row["sources"]
        ):
            raise ValueError(
                f"{row['name']}: source roots must be relative to the repository"
            )
    return manifest, rows


def pinned_rows(state, wanted):
    rows = read_json(state / "replay-projects.json")
    if len(rows) != len(wanted):
        raise ValueError("prepared and selected project counts differ")
    for row, expected in zip(rows, wanted, strict=True):
        if any(row.get(key) != value for key, value in expected.items()):
            raise ValueError(f"{expected['name']}: prepared source differs from pin")
        path = state / "sources" / expected["name"]
        if Path(row["path"]).resolve() != path or capture.verify_checkout(row) != path:
            raise ValueError(f"{expected['name']}: checkout is outside replay state")
    return rows


def prepare(state, rows):
    require_disk(state)
    # The state directory stays private on the host. Source files need to be
    # readable when the scanner mounts each checkout with its own container UID.
    old_mask = os.umask(0o022)
    try:
        ready = [checkout(state, row) for row in rows]
    finally:
        os.umask(old_mask)
    write_json_atomic(state / "replay-projects.json", ready)
    pinned_rows(state, rows)


def verify_reference_environment(environment, expected):
    analyzers = {
        item["key"]: {"version": item["version"], "jar_hash": item["hash"]}
        for item in environment["plugins"]["plugins"]
    }
    if (
        environment["navigation"]["edition"] != expected["edition"]
        or environment["server"]["version"] != expected["version"]
        or environment["server_image"] != expected["server_image"]
        or environment["scanner_image"] != expected["scanner_image"]
        or analyzers != expected["analyzers"]
    ):
        raise ValueError("reference environment differs from the recorded build")


def verify_profiles(directory, expected):
    effective = read_json(directory / "effective.json")["profiles"]
    normalized = {}
    for language, metadata in effective.items():
        rules = {}
        for page in directory.glob(f"effective-{language}-page-*.json"):
            for rule, activations in read_json(page)["actives"].items():
                [entry] = [
                    a for a in activations if a["qProfile"] == metadata["profile_key"]
                ]
                original = metadata["rules"][rule]
                if (
                    rule in rules
                    or {p["key"]: p["value"] for p in entry["params"]}
                    != original["parameters"]
                ):
                    raise ValueError(f"{language}: inconsistent activation for {rule}")
                rules[rule] = {**original, "severity": entry["severity"]}
        if rules.keys() != metadata["rules"].keys():
            raise ValueError(f"{language}: incomplete activation inventory")
        normalized[language] = {k: metadata[k] for k in ("name", "builtin", "default")}
        normalized[language]["rules"] = rules
    if (
        comparison.canonical_sha(normalized)
        != expected["effective_profile_content_sha256"]
    ):
        raise ValueError(
            "effective quality profiles differ from the recorded configuration"
        )
    return effective


def execute(row, args, output, reference, sonar=None, token=""):
    if reference:
        try:
            sonar.request("/api/components/show", {"component": row["project_key"]})
        except HTTPError as error:
            if error.code != 404:
                raise
        else:
            raise ValueError(f"{row['name']}: use a fresh reference project key")
    status = capture.execute(
        row,
        SimpleNamespace(
            output=output,
            binary=args.binary,
            reference_only=reference,
            native_only=not reference,
            no_shared_cache=not reference,
            state=args.state,
        ),
        sonar,
        token,
    )
    phase = "reference" if reference else "native"
    print(phase, row["name"], status[phase]["status"], flush=True)
    return status[phase]["status"]


def capture_reference(args, expected, rows):
    capture.SERVER, capture.NETWORK, capture.CACHE = (
        args.server,
        args.network,
        args.cache,
    )
    capture.verify_local_reference(args.state)
    password_path = args.state / "local-admin-password"
    if (
        not (args.state / "local-reference-token").exists()
        and not password_path.exists()
    ):
        # Seed a password with the character classes the reference validates.
        password = secrets.token_urlsafe(40) + "Aa4!"
        capture.DockerSonar("admin:admin").request(
            "/api/users/change_password",
            {"login": "admin", "previousPassword": "admin", "password": password},
            post=True,
        )
        password_path.write_text(password + "\n")
    token = capture.bootstrap(args.state)
    live = capture.DockerSonar(token + ":")
    environment = capture.reference_environment(live)
    verify_reference_environment(environment, expected)
    pilot = args.state / "pilot"
    output = args.state / "captures"
    pilot.mkdir()
    output.mkdir()
    write_json_atomic(args.state / "reference-environment.json", environment)
    first = next(row for row in rows if row["name"] == PILOT)
    if execute(first, args, pilot, True, live, token) != "complete":
        raise RuntimeError("reference pilot did not complete")
    profiles.capture_effective_profiles(args.state, live)
    verify_profiles(args.state / "profiles", expected)
    frozen = profiles.FrozenProfileSonar(token + ":", pilot / PILOT)
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        list(
            pool.map(
                lambda row: execute(row, args, output, True, frozen, token),
                [r for r in rows if r != first],
            )
        )
    profiles.capture_effective_profiles(args.state, live, refresh=True)
    verify_profiles(args.state / "profiles-end", expected)


def capture_native(args, manifest, rows):
    if args.binary is None:
        raise ValueError("--binary is required for native capture")
    args.binary = args.binary.resolve(strict=True)
    observed_sha = capture.oracle.digest(args.binary)
    if observed_sha != manifest["native_binary_sha256"]:
        if args.native_checkout is None:
            raise ValueError(
                "use the recorded binary or pass --native-checkout for a rebuild"
            )
        source = args.native_checkout.resolve(strict=True)

        def git(*command):
            return subprocess.check_output(
                ["git", "-C", str(source), *command], text=True
            ).strip()

        if (
            git("rev-parse", "HEAD") != manifest["native_commit"]
            or git("rev-parse", "HEAD^{tree}") != manifest["native_tree"]
            or git("status", "--porcelain", "--untracked-files=no")
            or args.binary != (source / "target/release/hoonarqube").resolve()
        ):
            raise ValueError(
                "pass the release binary from the clean pinned Hoonarqube checkout"
            )
    output = args.state / "native" / manifest["native_commit"]
    output.mkdir(parents=True)
    write_json_atomic(
        output / "build.json",
        {
            "commit": manifest["native_commit"],
            "tree": manifest["native_tree"],
            "binary_sha256": observed_sha,
            "matches_recorded_binary": observed_sha == manifest["native_binary_sha256"],
        },
    )
    raw_catalog = subprocess.check_output([str(args.binary), "rules", "list", "--json"])
    write_json_atomic(output / "rule-catalog.json", json.loads(raw_catalog))
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        list(pool.map(lambda row: execute(row, args, output, False), rows))


def summarize(state, manifest, provenance, rows):
    expected = provenance["reference"]
    verify_reference_environment(
        read_json(state / "reference-environment.json"), expected
    )
    effective = verify_profiles(state / "profiles", expected)
    if effective != verify_profiles(state / "profiles-end", expected):
        raise ValueError(
            "effective profile settings changed during the reference scans"
        )
    native = state / "native" / manifest["native_commit"]
    build = read_json(native / "build.json")
    if (build["commit"], build["tree"]) != (
        manifest["native_commit"],
        manifest["native_tree"],
    ):
        raise ValueError("recorded native source does not match the manifest")
    catalog = {
        r["external_key"]: r["rule_type"]
        for r in read_json(native / "rule-catalog.json")
    }
    infra, boundaries_sha, _ = comparison.verified_boundaries(manifest["native_commit"])
    if boundaries_sha != provenance["implementation_boundaries_sha256"]:
        raise ValueError("implementation boundaries differ from the recorded source")
    counts = Counter()
    findings = Counter(dict.fromkeys(("matched", "native_only", "reference_only"), 0))
    metrics = Counter(compared_cells=0, matched_cells=0)
    files = 0
    for row in rows:
        name = row["name"]
        reference = state / ("pilot" if name == PILOT else "captures") / name
        if read_json(reference / "source.json") != row:
            raise ValueError(
                f"{name}: reference capture differs from the prepared sources"
            )
        result = comparison.summarize_project(
            reference, effective, catalog, infra, native / name
        )
        disposition = result["comparison_state"]
        counts[disposition] += 1
        if disposition == "same_scope":
            files += result["files"]["shared"]
            findings.update(
                result["findings"]["shared_files"]["by_class"].get(
                    "shared_equal_declared_parameters", {}
                )
            )
            cells = result["metrics"]["shared_file_metrics"]
            metrics.update(
                {key: cells[key] for key in ("compared_cells", "matched_cells")}
            )
    return {
        "native_binary_matches_recorded_build": build["binary_sha256"]
        == manifest["native_binary_sha256"],
        "comparison_states": dict(counts),
        "identical_files": files,
        "primary_findings_on_identical_scopes": dict(findings),
        "file_metrics_on_identical_scopes": dict(metrics),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "reference", "native", "summary"))
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--native-checkout", type=Path)
    parser.add_argument("--jobs", type=int, choices=(1, 2), default=2)
    parser.add_argument("--server", default="hq-wave3-replay-reference")
    parser.add_argument("--network", default="hq-wave3-replay-network")
    parser.add_argument("--cache", default="hq-wave3-replay-cache")
    args = parser.parse_args()
    args.state = args.state.resolve(strict=True)
    if not args.state.is_dir() or args.state.stat().st_mode & 0o077:
        parser.error("--state must be a private directory (mode 0700)")
    os.umask(0o077)
    os.environ["GIT_OPTIONAL_LOCKS"] = "0"
    profiles.install_capture_constraints()
    profiles.PILOT = PILOT
    manifest, wanted = load_manifest(args.manifest)
    receipt = read_json(RECEIPT)
    if comparison.canonical_sha(manifest) != receipt["manifest_sha256"]:
        raise ValueError("manifest does not match the qualification receipt")
    provenance = receipt["provenance"]
    if args.phase == "prepare":
        prepare(args.state, wanted)
        return
    rows = pinned_rows(args.state, wanted)
    if args.phase == "reference":
        capture_reference(args, provenance["reference"], rows)
    elif args.phase == "native":
        for variable in ("NODE_PATH", "HOONARQUBE_TYPESCRIPT_PACKAGE"):
            os.environ.pop(variable, None)
        capture_native(args, manifest, rows)
    else:
        print(json.dumps(summarize(args.state, manifest, provenance, rows), indent=2))


if __name__ == "__main__":
    main()
