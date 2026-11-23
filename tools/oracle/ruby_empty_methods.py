"""Compare Ruby S1186 primary locations and messages on pinned public sources."""

import argparse
from collections import Counter
import gzip
import json
from pathlib import Path
import re
import subprocess
import tempfile

from public_contract import require, safe_path, stage
from public_corpus_summary import normalize_native

MANIFEST = Path(__file__).parent / "fixtures/ruby-s1186-public-20261122.json.gz"
RULE = "ruby:S1186"


def replay(case, binary, local_repo):
    with tempfile.TemporaryDirectory(prefix="ruby-empty-methods-") as temp:
        safe_path(case["repository"])
        require(case["repository"].count("/") == 1, "invalid project name")
        for field in ("commit", "tree"):
            require(re.fullmatch("[0-9a-f]{40}", case[field]), f"invalid {field}")
        for path in case["files"]:
            safe_path(path)
        source = stage(case, Path(temp), local_repo)
        run = subprocess.run(
            [
                binary,
                "analyze",
                *sorted(case["files"]),
                "--format",
                "json",
                "--profile",
                "sonar-parity",
            ],
            cwd=source,
            timeout=180,
            capture_output=True,
            check=False,
        )
        if run.returncode:
            detail = run.stderr.decode(errors="replace").strip().splitlines()
            raise ValueError(
                f"analyzer exit {run.returncode}: " + "; ".join(detail[:4])
            )
        report = json.loads(run.stdout)
        require(
            report["project"]["complete"]
            and not report["parity"]["rule_set_violations"],
            "incomplete scan",
        )
        for rows in (report["files"], report["project"]["files"]):
            require(
                Counter(f["path"] for f in rows) == Counter(case["files"].keys()),
                "different file scope",
            )
        selected = [
            {**f, "issues": [i for i in f["issues"] if i["rule_key"] == RULE]}
            for f in report["files"]
        ]
        _, messages, _, invalid = normalize_native(selected, source, {}, {})
        require(not invalid, f"invalid primary coordinates: {invalid}")
        native = Counter({identity[1:]: n for identity, n in messages.items()})
        expected = Counter(map(tuple, case["issues"]))
        return {
            "exact": sum((native & expected).values()),
            "native_only": list((native - expected).elements()),
            "reference_only": list((expected - native).elements()),
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument(
        "--case", action="append", help="Repeat to select individual projects."
    )
    parser.add_argument(
        "--local-repositories",
        type=Path,
        help="Optional JSON map from case name to pinned Git checkout.",
    )
    parser.add_argument("--output", type=Path, help="Write per-project differences.")
    args = parser.parse_args()
    local = (
        json.loads(args.local_repositories.read_bytes())
        if args.local_repositories
        else None
    )
    corpus = json.loads(gzip.decompress(MANIFEST.read_bytes()))
    require(
        corpus["rule"] == RULE and corpus["community_build"] == "26.9.0.129388",
        "unexpected reference",
    )
    cases = corpus["cases"]
    require(
        not args.case or set(args.case) <= {c["name"] for c in cases}, "unknown project"
    )
    results = {}
    for case in cases:
        name = case["name"]
        if args.case and name not in args.case:
            continue
        try:
            result = replay(
                case,
                args.binary.resolve(),
                Path(local[name]) if local is not None else None,
            )
        except (ValueError, OSError, KeyError, subprocess.SubprocessError) as err:
            results[name] = {"error": str(err)}
            print(f"{name}: comparison failed: {err}", flush=True)
            continue
        results[name] = result
        print(
            f"{name}: {len(case['files'])} files, {result['exact']} exact, "
            f"{len(result['native_only'])} native only, {len(result['reference_only'])} reference only",
            flush=True,
        )
    if args.output:
        args.output.write_text(json.dumps(results, indent=2) + "\n")
    if any(
        "error" in r or r["native_only"] or r["reference_only"]
        for r in results.values()
    ):
        raise SystemExit(
            "At least one comparison failed or differed from its pinned Community reference."
        )


if __name__ == "__main__":
    main()
