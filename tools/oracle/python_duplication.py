"""Replay complete Python package scopes against immutable Community CPD captures."""

import argparse
from collections import Counter
import gzip
import json
from pathlib import Path
import re
import subprocess
import tempfile

from public_contract import require, safe_path, stage

MANIFEST = Path(__file__).parent / "fixtures/python-duplication-public-20261122.json.gz"
METRICS = ("duplicated_lines", "duplicated_blocks")


def positive_files(report):
    """Union overlapping source ranges; project totals alone can conceal file errors."""
    ranges = {}
    for group in report["project"]["duplications"]:
        for copy in group["occurrences"]:
            ranges.setdefault(copy["path"], []).append(
                (copy["start_line"], copy["end_line"])
            )
    result = {}
    for record in report["project"]["files"]:
        path = record["path"]
        spans = []
        for first, last in sorted(ranges.pop(path, [])):
            require(1 <= first <= last, "invalid line span")
            if spans and first <= spans[-1][1] + 1:
                spans[-1][1] = max(spans[-1][1], last)
            else:
                spans.append([first, last])
        require(
            sum(b - a + 1 for a, b in spans)
            == record["duplication"]["duplicated_lines"],
            "range union differs from reported line count",
        )
        if spans:
            result[path] = {
                "blocks": record["duplication"]["duplicated_blocks"],
                "ranges": spans,
            }
    require(not ranges, "duplication reported outside file metrics")
    return result


def validate(case):
    safe_path(case["repository"])
    require(case["repository"].count("/") == 1, "invalid repository")
    for name in ("commit", "tree"):
        require(re.fullmatch("[a-f0-9]{40}", case[name]), f"invalid {name}")
    for name in ("task", "analysis"):
        require(
            re.fullmatch("[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", case[name]),
            f"invalid {name}",
        )
    require(
        set(case["reference"]) == set(METRICS) and case["files"],
        "missing counts or input",
    )
    require(
        re.fullmatch("[a-f0-9]{64}", case["measures_sha256"]), "invalid measures digest"
    )
    for path, digest in case["files"].items():
        safe_path(path)
        require(re.fullmatch("[a-f0-9]{64}", digest), "invalid blob digest")


def compare(case, binary, local_repo):
    validate(case)
    with tempfile.TemporaryDirectory(prefix="python-cpd-") as tmp:
        root = stage(case, Path(tmp), local_repo)
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
            cwd=root,
            capture_output=True,
            check=True,
            timeout=240,
        )
        report = json.loads(run.stdout)
        project = report["project"]
        require(
            project["complete"] and not report["parity"]["rule_set_violations"],
            "incomplete report",
        )
        require(
            report["parity"]["reference"]["profile"] == "sonar-parity"
            and all(
                f["status"] == "complete" and f["classification"] == "source"
                for f in project["files"]
            ),
            "wrong profile or incomplete source classification",
        )
        for rows in (project["files"], report["files"]):
            require(
                Counter(f["path"] for f in rows) == Counter(case["files"].keys()),
                "different input inventory",
            )
        counts = {k: project["duplication"][k] for k in METRICS}
        require(
            counts == case["reference"],
            f"actual {counts}, reference {case['reference']}",
        )
        if "by_file" in case:
            actual = positive_files(report)
            require(
                actual == case["by_file"],
                "different duplicate ranges or block counts in "
                + ", ".join(
                    sorted(
                        k
                        for k in actual.keys() | case["by_file"].keys()
                        if actual.get(k) != case["by_file"].get(k)
                    )
                ),
            )
        return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--case", action="append")
    parser.add_argument(
        "--local-repositories",
        type=Path,
        help="Optional JSON map of case names to pinned Git repositories.",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    corpus = json.loads(gzip.decompress(MANIFEST.read_bytes()))
    require(
        corpus["community_build"] == "26.9.0.129388"
        and corpus["python_plugin"] == "5.31.0.36502",
        "unexpected reference versions",
    )
    cases = corpus["cases"]
    names = {c["name"] for c in cases}
    require(
        len(names)
        == len(cases)
        == len({c["analysis"] for c in cases})
        == len({c["task"] for c in cases})
        == 47,
        "missing or repeated reference",
    )
    require(not args.case or set(args.case) <= names, "unknown public project")
    local = (
        json.loads(args.local_repositories.read_bytes())
        if args.local_repositories
        else {}
    )
    results = {}
    for case in cases:
        name = case["name"]
        if args.case and name not in args.case:
            continue
        try:
            results[name] = compare(
                case,
                args.binary.resolve(strict=True),
                Path(local[name]) if args.local_repositories else None,
            )
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            results[name] = {"error": str(error)}
        print(f"{name}: {results[name]}", flush=True)
    if args.output:
        args.output.write_text(json.dumps(results, indent=2) + "\n")
    if any("error" in row for row in results.values()):
        raise SystemExit("Public Python duplication comparison failed.")


if __name__ == "__main__":
    main()
