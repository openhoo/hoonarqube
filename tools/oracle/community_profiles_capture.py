"""Freeze ordinary finding locations from three freshly measured Community profiles."""

import argparse
import gzip
import json
from pathlib import Path

from community_profiles import LANGUAGES, TIERS, VERSION, check_bundle
from public_contract import require
from public_corpus_summary import source_indexes
from public_corpus_wave3_replay import verify_profiles, verify_reference_environment
from public_locations_capture import capture, digest, read

OBSERVATIONS = {"parameters", "sonar", "missing", "extra", "evidence"}
SERVER = (
    "sonarqube@sha256:7b2296713a92b8ea0dd7a083a25faadc59376c9a1e6daf2744a89711c54ea1ba"
)


def missing_languages(root, originals):
    env = read(root / "reference-environment.json")
    langs = {entry["key"] for entry in env["languages"]["languages"]}
    require(not langs.intersection({"rust", "ruby"}), "unexpected installed language")
    receipt = read(root / "cohort-receipt.json")
    missing = []
    by_repo = {v["repository"]: v for v in originals.values()}
    for item in receipt["projects"]:
        if item["language"] in LANGUAGES:
            continue
        orig = by_repo[item["repository"]]
        name = orig["name"]
        ref = root / "reference" / name
        files = {k: v["sha256"] for k, v in orig["source_inventory"].items()}
        src = root / "sources" / name
        require(
            item["comparison_state"] == "not_compared_reference_language_absent"
            and item["reference"]["state"] == "complete"
            and not source_indexes(ref, src, "reference")
            and source_indexes(root / "native" / name, src, "native") == files,
            "unavailable source scope differs",
        )
        task = read(ref / "compute-engine.json")["task"]
        require(
            task["status"] == "SUCCESS"
            and task["analysisId"] == item["reference"]["analysis_id"]
            and task["id"] == item["reference"]["task_id"],
            "missing compute receipt",
        )
        missing.append(
            {
                "repository": item["repository"],
                "repository_id": orig["repository_id"],
                "language": item["language"],
                "commit": item["commit"],
                "files": len(files),
                "analysis": task["analysisId"],
                "task": task["id"],
            }
        )
    return missing


def export(root, frozen):
    root = root.resolve(strict=True)
    original = {row["name"]: row for row in read(frozen)["projects"]}
    require(len(original) == 24, "wrong original cohort")
    metadata, combined = {}, {}
    baseline = None
    for tier in TIERS:
        state = root if tier == "core" else root / ("assigned-" + tier)
        env = read(state / "environment-contract.json")
        require(
            env["version"] == VERSION
            and env["edition"] == "community"
            and env["server_image"]["image"] == SERVER,
            "wrong Community image",
        )
        for suffix in ("", "-end"):
            verify_reference_environment(
                read(state / ("reference-environment" + suffix + ".json")), env
            )
        expected = read(state / "profile-contract.json")
        effective = verify_profiles(state / "profiles", expected)
        verify_profiles(state / "profiles-end", expected)
        rows = []
        for r in read(state / "prepared.json"):
            old = original[r["name"]]
            require(
                all(
                    old[k] == r[k]
                    for k in (
                        "commit",
                        "tree",
                        "repository",
                        "language",
                        "sources",
                        "scope_root",
                        "exclude",
                        "source_inventory",
                    )
                ),
                "source selection changed",
            )
            if r["language"] in LANGUAGES:
                rows.append({**r, "repository_id": old["repository_id"]})
        data = capture(state, expected_version=VERSION, selected_rows=rows)
        if baseline is None:
            baseline = data["baseline"]
        require(baseline == data["baseline"], "native baseline changed")
        metadata[tier] = {
            "configuration_sha256": expected["effective_profile_content_sha256"],
            "receipt_sha256": data["receipt_sha256"],
            "languages": {
                lang: {
                    "name": effective[lang]["name"],
                    "builtin": effective[lang]["builtin"],
                    "active_keys": len(effective[lang]["rules"]),
                }
                for lang in sorted(LANGUAGES)
            },
        }
        for case in data["projects"]:
            scope = {k: v for k, v in case.items() if k not in OBSERVATIONS}
            saved = combined.setdefault(
                case["repository"], {**scope, "observations": {}}
            )
            require(
                all(saved[k] == v for k, v in scope.items()),
                "native scope changed between profiles",
            )
            saved["observations"][tier] = {
                **{k: case[k] for k in sorted(OBSERVATIONS)},
                "configuration_sha256": expected["effective_profile_content_sha256"],
            }
    bundle = {
        "format": 1,
        "sonar": VERSION,
        "baseline": baseline,
        "profiles": metadata,
        "source_manifest_sha256": digest(frozen),
        "projects": list(combined.values()),
        "without_reference_language": missing_languages(root, original),
    }
    check_bundle(bundle)
    return bundle


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("archive", type=Path)
    cli.add_argument("source_manifest", type=Path)
    cli.add_argument("output", type=Path)
    args = cli.parse_args()
    data = export(args.archive, args.source_manifest)
    args.output.write_bytes(
        gzip.compress(
            (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode(),
            mtime=0,
        )
    )


if __name__ == "__main__":
    main()
