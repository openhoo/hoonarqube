"""Build the 24-repository regression fixture from archived independent analyses."""

import argparse
import gzip
import hashlib
import json
from collections import Counter
from pathlib import Path

from public_contract import canonical_sha, observe, require
from public_contract_capture import captured_issues
from public_corpus_summary import (
    check_profiles,
    normalize_reference,
    source_indexes,
    verified_boundaries,
)


def read(p):
    return json.loads(p.read_bytes())


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def capture(state, *, expected_version="26.9.0.129388", selected_rows=None):
    receipt = read(state / "cohort-receipt.json")
    if selected_rows is None:
        selected_rows = read(state / "cohort-frozen.json")["projects"]
    require(
        receipt["reference"]["server"]["version"] == expected_version,
        "wrong Community release",
    )
    require(
        receipt["native"]["source_tree"] == receipt["native"]["compiled_tree"],
        "different compiled tree",
    )
    source = receipt["native"]["source_commit"]
    gaps, _, _ = verified_boundaries(source)
    types = {
        r["external_key"]: r["rule_type"] for r in read(state / "native-catalog.json")
    }
    effective = read(state / "profiles/effective.json")["profiles"]
    rows = {c["repository"]: c for c in receipt["projects"]}
    cases = []
    for row in selected_rows:
        name = row["name"]
        measurement = rows[row["repository"]]
        refs = [
            p / name
            for p in (state / "pilot", state / "reference")
            if (p / name / "compute-engine.json").is_file()
        ]
        (ref,) = refs
        job = read(ref / "compute-engine.json")["task"]
        require(
            job["status"] == "SUCCESS"
            and job["componentKey"] == row["project_key"]
            and job["analysisId"] == measurement["reference"]["analysis_id"]
            and job["id"] == measurement["reference"]["task_id"],
            "reference analysis mismatch",
        )
        native_dir = state / "native" / name
        native = read(native_dir / "native.json")
        root = (state / "sources" / name).resolve(strict=True)
        files = {k: v["sha256"] for k, v in row["source_inventory"].items()}
        require(
            measurement["comparison_state"] == "same_scope"
            and files
            == source_indexes(ref, root, "reference")
            == source_indexes(native_dir, root, "native")
            and measurement["commit"] == row["commit"]
            and measurement["tree"] == row["tree"]
            and all(
                hashlib.sha256((root / path).read_bytes()).hexdigest() == sha
                for path, sha in files.items()
            ),
            "scope differs",
        )
        expected_hashes = measurement["evidence_sha256"]
        for directory, names in (
            (ref, ("issues.json", "scanner.stdout")),
            (native_dir, ("native.stdout",)),
        ):
            for filename in names:
                require(
                    digest(directory / filename) == expected_hashes[filename],
                    "capture digest mismatch",
                )
        require(receipt["reference_profiles_verified"], "unverified Community profile")
        profile = check_profiles(ref, effective)
        # Only compare ordinary native and Sonar issues. The source cohort qualified
        # native hotspots separately; compare the same population on each replay.
        params = {}
        for rule in native["parity"]["active_rules"]:
            k = rule["key"]
            defaults = {
                p["key"]: p["default_value"]
                for p in rule["parameters"]
                if p.get("default_value") is not None
            }
            if (
                k not in gaps
                and k in profile
                and profile[k]["type"] != "SECURITY_HOTSPOT"
                and types[k] != "SECURITY_HOTSPOT"
                and profile[k]["parameters"] == defaults
            ):
                params[k] = defaults
        sonar, _, _, outside = normalize_reference(
            captured_issues(ref), row["project_key"], files
        )
        require(not outside, "out-of-scope reference issue")
        reference = Counter({k: n for k, n in sonar.items() if k[0] in params})
        case = {
            k: row[k]
            for k in (
                "name",
                "repository",
                "repository_id",
                "language",
                "tree",
                "commit",
                "sources",
                "exclude",
            )
        }
        ordered = native["parity"]["scope"]["roots"]
        require(Counter(ordered) == Counter(row["sources"]), "root inventory differs")
        case["sources"] = ordered
        case.update(
            files=files,
            source_inventory_sha256=canonical_sha(files),
            semantic_context=native["parity"]["semantic_context"],
            parameters=params,
        )
        found = observe(case, native, root)
        missing, extra = reference - found, found - reference
        counts = {
            "matched": (found & reference).total(),
            "native_only": extra.total(),
            "reference_only": missing.total(),
        }
        require(
            all(n == measurement["primary"].get(k, 0) for k, n in counts.items()),
            f"{name}: primary counts differ {counts} != {measurement['primary']}",
        )
        case.update(
            sonar=sorted(reference.elements()),
            missing=sorted(missing.elements()),
            extra=sorted(extra.elements()),
            evidence={
                "analysis": job["analysisId"],
                "task": job["id"],
                "issues_sha256": expected_hashes["issues.json"],
                "native_sha256": expected_hashes["native.stdout"],
                "scanner_log_sha256": expected_hashes["scanner.stdout"],
            },
        )
        cases.append(case)
    return {
        "format": 1,
        "baseline": source,
        "sonar": expected_version,
        "receipt_sha256": digest(state / "cohort-receipt.json"),
        "projects": cases,
    }


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("archive", type=Path)
    cli.add_argument("output", type=Path)
    args = cli.parse_args()
    result = capture(args.archive)
    args.output.write_bytes(
        gzip.compress(
            (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode(),
            mtime=0,
        )
    )


if __name__ == "__main__":
    main()
