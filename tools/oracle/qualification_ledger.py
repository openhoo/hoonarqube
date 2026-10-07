#!/usr/bin/env python3
"""Enumerate frozen qualification gaps without reclassifying old evidence.

This ledger is a finite work inventory, not a current binary qualification.
New measurements must identify their exact source, binary, scope and reference.
"""

import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path


def load(path):
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt") as stream:
        return json.load(stream)


def ledger(root):
    corpus_path = root / "full-corpus-qualification-20260910.json.gz"
    security_path = root / "security-qualification-20260910.json"
    quickfix_path = root / "quickfix-qualification-20260910.json.gz"
    corpus, security, quickfix = map(load, [corpus_path, security_path, quickfix_path])
    corpus_rows = []
    for project, matrix in sorted(corpus["matrices"].items()):
        for row in matrix["rows"]:
            if row["status"] == "PASS":
                continue
            corpus_rows.append(
                {
                    "project": project,
                    "rule": row["key"],
                    "historical_status": row["status"],
                    "observed_status": row.get("observed_status"),
                    "bad": row.get("bad"),
                    "good": row.get("good"),
                    "native_complete": row.get("native_complete"),
                    "reason": row.get("reason", ""),
                    "next_evidence": "Fresh pinned per-fixture native and reference execution; "
                    "preserve malformed fixture incompleteness and all profile/range/message data.",
                }
            )
    applications = []
    for language, result in sorted(quickfix["languages"].items()):
        applications.extend(
            {
                "language": language,
                "rule": row["rule_key"],
                "row_index": row["row_index"],
                "action_id": row.get("action_id"),
                "historical_status": row["status"],
                "next_evidence": "Replay projection, apply, no-write negatives and reanalysis "
                "against final binary; preserve safety refusals as separate outcomes.",
            }
            for row in result["applications"]
        )
    enterprise = [
        {
            "rule": row["key"],
            "sensor": row["sensor_ownership"]["enterprise_security_sensor"],
            "historical_status": row["reference_status"],
            "local_direct_analyzer": row["context"]["local_direct_analyzer"],
            "licensed_server_sensor": row["context"]["licensed_server_sensor"],
            "next_evidence": "Licensed applicable server sensor, pinned scanner/.NET "
            "build, effective profile, raw issues/security flows and rule ownership.",
        }
        for row in security["enterprise_unverified"]["rows"]
    ]
    return {
        "schema_version": 1,
        "kind": "historical_residual_acceptance_inventory",
        "claim": "No current release parity inferred from historical statuses.",
        "inputs": [
            {
                "path": str(path.relative_to(root)),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            for path in [corpus_path, security_path, quickfix_path]
        ],
        "summary": {
            "corpus_nonpass_rows": len(corpus_rows),
            "corpus_by_status": dict(
                sorted(Counter(row["historical_status"] for row in corpus_rows).items())
            ),
            "quickfix_replay_rows": len(applications),
            "quickfix_by_status": dict(
                sorted(
                    Counter(row["historical_status"] for row in applications).items()
                )
            ),
            "enterprise_unverified_rules": len(enterprise),
        },
        "corpus": corpus_rows,
        "quickfix": applications,
        "enterprise": enterprise,
        "closure_gates": {
            "secondary_flows": "Compare primary messages plus flows with ordered locations "
            "and multiplicity using secondary_locations.py. API flow order is not significant.",
            "security": "Do not count unavailable hotspot/review/flow fields as equal.",
            "quickfix": "Historical pass is a replay candidate; safety_refused and "
            "no_action_expected are not edit equivalence passes.",
            "codeql": "Fresh default setup run must upload successfully; frozen Rust "
            "job cannot be rerun (HTTP403 Jobs in this workflow run cannot be re-run).",
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).parent)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = ledger(args.root)
    encoded = (json.dumps(result, indent=2) + "\n").encode()
    args.output.write_bytes(
        gzip.compress(encoded, mtime=0) if args.output.suffix == ".gz" else encoded
    )
    print(result["summary"])


if __name__ == "__main__":
    main()
