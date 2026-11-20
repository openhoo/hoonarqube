#!/usr/bin/env python3
"""Capture the second static corpus with independent live reference and native reports."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
from itertools import zip_longest
from pathlib import Path

import public_corpus_capture as capture
from parity import read_json, write_json_atomic
from public_corpus_wave2_prepare import PLANS, require_disk

REFERENCE = "hq-public-wave2-reference-20261120"
NETWORK = "hq-public-wave2-local-20261120"
CACHE = "hq-public-wave2-scanner-cache-20261120"
PILOT = "itsdangerous"
BINARY_SHA256 = "e719261d0fe6db1f53d362da0ec55b3da152d4a9ec7034474b56018124552021"
HELPER_GLOB = "**/.hoonarqube/semantic/typescript/semantic-helper-v1.cjs"


def helper_paths(row, root):
    if row["language"] in {"js", "ts"}:
        yield from sorted(root.glob(HELPER_GLOB))


def archive_generated_helpers(row, root, folder):
    source_roots = tuple((root / rel).resolve() for rel in row["sources"])
    for helper in helper_paths(row, root):
        if (
            not helper.is_file()
            or helper.resolve() != helper
            or any(helper.is_relative_to(path) for path in source_roots)
            or capture.oracle.digest(helper) != capture.ZOD_HELPER_SHA256
        ):
            raise ValueError(
                f"{row['name']}: unexpected helper; retain checkout unchanged"
            )
        destination = folder / "generated" / helper.relative_to(root)
        if os.path.lexists(destination):
            raise ValueError("generated helper capture already exists")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(helper, destination)


def install_capture_constraints():
    capture.SERVER = REFERENCE
    capture.NETWORK = NETWORK
    capture.CACHE = CACHE
    ordinary_verify = capture.verify_checkout
    ordinary_execute = capture.execute

    def strict_verify(row):
        root = ordinary_verify(row)
        if next(helper_paths(row, root), None) is not None:
            raise ValueError("pre-existing semantic helper in the pinned checkout")
        return root

    def budgeted_execute(row, args, sonar, token):
        require_disk(args.state)
        try:
            return ordinary_execute(row, args, sonar, token)
        except Exception as error:
            # Keep the raw snapshots if final checkout verification failed,
            # while preventing the summary from comparing this row.
            progress = args.output / row["name"] / "progress.json"
            if progress.is_file():
                partial = read_json(progress)
                write_json_atomic(
                    progress.with_name("progress-before-guard.json"), partial
                )
                partial["native"] = {"status": "failed", "reason": str(error)}
                write_json_atomic(progress, partial)
            raise

    capture.verify_checkout = strict_verify
    capture.execute = budgeted_execute
    capture.preserve_native_helper = archive_generated_helpers


def recorded_profiles(pilot):
    return sorted(
        read_json(pilot / "profiles.json")["profiles"], key=lambda v: v["language"]
    )


def profile_signature(profiles):
    keys = (
        "language",
        "key",
        "name",
        "isBuiltIn",
        "isDefault",
        "activeRuleCount",
        "rulesUpdatedAt",
    )
    return sorted(tuple(v.get(k) for k in keys) for v in profiles)


class FrozenProfileSonar(capture.DockerSonar):
    """Reuse independently verified active rule pages on the dedicated server."""

    def __init__(self, auth, pilot):
        super().__init__(auth)
        self.signature = profile_signature(recorded_profiles(pilot))
        self.pilot_pages = {}
        for profile in recorded_profiles(pilot):
            label = "active-" + profile["language"]
            pages = tuple(sorted(pilot.glob(f"{label}-page-*.json")))
            rules = tuple(rule for page in pages for rule in read_json(page)["rules"])
            if len(rules) != profile["activeRuleCount"]:
                raise ValueError(f"frozen rule page count differs for {label}")
            self.pilot_pages[profile["key"]] = (label, pages, rules)

    def request(self, path, params=None, post=False):
        received = super().request(path, params, post)
        if (
            path == "/api/qualityprofiles/search"
            and params
            and "project" in params
            and profile_signature(received["profiles"]) != self.signature
        ):
            raise ValueError("project profile differs from the live pilot profile")
        return received

    def pages(self, path, params, field, folder, label):
        if (
            path == "/api/rules/search"
            and field == "rules"
            and set(params) == {"qprofile", "activation"}
            and params["activation"] == "true"
        ):
            expected, pages, rules = self.pilot_pages[params["qprofile"]]
            if label != expected:
                raise ValueError("active rules requested with wrong language label")
            for page in pages:
                os.link(page, folder / page.name)
            return list(rules)
        return super().pages(path, params, field, folder, label)


def capture_effective_profiles(state, sonar, refresh=False):
    pilot = state / "pilot" / PILOT
    folder = state / ("profiles-end" if refresh else "profiles")
    folder.mkdir()
    row = read_json(pilot / "source.json")
    live = sonar.request("/api/qualityprofiles/search", {"project": row["project_key"]})
    if profile_signature(live["profiles"]) != profile_signature(
        recorded_profiles(pilot)
    ):
        raise ValueError("live project profile differs from pilot")
    result = {}
    for profile in recorded_profiles(pilot):
        language = profile["language"]
        rules = sonar.pages(
            "/api/rules/search",
            {"qprofile": profile["key"], "activation": "true", "f": "actives,params"},
            "rules",
            folder,
            f"effective-{language}",
        )
        metadata = {
            r["key"]: r
            for page in pilot.glob(f"active-{language}-page-*.json")
            for r in read_json(page)["rules"]
        }
        if len(rules) != profile["activeRuleCount"] or metadata.keys() != {
            r["key"] for r in rules
        }:
            raise ValueError(f"{language}: active rule inventory changed")
        config = {}
        for page in folder.glob(f"effective-{language}-page-*.json"):
            data = read_json(page)
            actives = data.get("actives", {})
            if actives.keys() != {r["key"] for r in data["rules"]}:
                raise ValueError(f"{language}: activation inventory incomplete")
            for key, values in actives.items():
                active = [a for a in values if a["qProfile"] == profile["key"]]
                if len(active) != 1:
                    raise ValueError(f"{language}: ambiguous activation {key}")
                config[key] = {p["key"]: p["value"] for p in active[0]["params"]}
        result[language] = {
            "name": profile["name"],
            "builtin": profile["isBuiltIn"],
            "default": profile["isDefault"],
            "profile_key": profile["key"],
            "rules": {
                key: {
                    "type": value["type"],
                    "scope": value["scope"],
                    "parameters": config[key],
                }
                for key, value in metadata.items()
            },
        }
    write_json_atomic(
        folder / "effective.json",
        {"captured_at_utc": capture.utc(), "profiles": result},
    )
    if refresh and result != read_json(state / "profiles/effective.json")["profiles"]:
        raise ValueError("effective quality profile changed during capture")
    print(f"Captured {len(result)} effective profiles; refresh={refresh}", flush=True)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--binary", type=Path)
    parser.add_argument(
        "phase", choices=["pilot", "profiles", "captures", "profiles-end"]
    )
    parser.add_argument("--jobs", type=int, choices=[1, 2], default=2)
    args = parser.parse_args()
    args.state = args.state.resolve()
    if args.phase != "profiles-end":
        require_disk(args.state)
    install_capture_constraints()
    token = capture.bootstrap(args.state)
    if args.phase in {"profiles", "profiles-end"}:
        capture_effective_profiles(
            args.state, capture.DockerSonar(token + ":"), args.phase == "profiles-end"
        )
        return 0
    if args.binary is None or capture.oracle.digest(args.binary) != BINARY_SHA256:
        parser.error("use the SHA-256 verified Foundation binary")
    args.binary = args.binary.resolve()
    args.output = args.state / args.phase
    args.output.mkdir(exist_ok=False)
    args.manifest = args.state / (
        "pilot-projects.json" if args.phase == "pilot" else "projects.json"
    )
    args.names = None
    args.reference_only = args.native_only = args.no_shared_cache = False
    sonar = (
        capture.DockerSonar(token + ":")
        if args.phase == "pilot"
        else FrozenProfileSonar(token + ":", args.state / "pilot" / PILOT)
    )
    write_json_atomic(
        args.output / "reference-environment.json", capture.reference_environment(sonar)
    )
    write_json_atomic(
        args.output / "native-binary.json",
        {
            "path": str(args.binary),
            "sha256": BINARY_SHA256,
            "version": subprocess.check_output(
                [str(args.binary), "--version"], text=True
            ).strip(),
        },
    )
    rows = capture.selected_rows(args)
    by_language = [
        [row for row in rows if row["language"] == language] for language in PLANS
    ]
    interleaved = [
        row for batch in zip_longest(*by_language) for row in batch if row is not None
    ]
    return capture.execute_manifest(args, interleaved, sonar, token)


if __name__ == "__main__":
    raise SystemExit(main())
