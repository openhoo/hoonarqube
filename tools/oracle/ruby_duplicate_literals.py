"""Compare Ruby S1192 messages, primary ranges and every independent duplication flow."""

import argparse
import gzip
import json
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from public_contract import require, safe_path
from ruby_rule_scan import analyze, pinned_source
from secondary_locations import compare

RULE = "ruby:S1192"
FIXTURES = Path(__file__).parent / "fixtures"


def manifest(group):
    data = json.loads(
        gzip.decompress(
            (FIXTURES / f"ruby-s1192-{group}-20261122.json.gz").read_bytes()
        )
    )
    require(
        data["rule"] == RULE and data["version"] == "26.9.0.129388", "wrong reference"
    )
    return data["cases"]


def replay(case, binary, local=None):
    with TemporaryDirectory(prefix="ruby-duplicates-") as temp:
        root = Path(temp)
        if "invalid_source" in case:
            # An unterminated regexp (also rejected by Ruby's syntax checker).
            # Community indexed the file without an S1192 finding. Native CI
            # must report incomplete input; never count it as matching silence.
            (root / "white.rb").write_bytes(case["invalid_source"].encode())
            run = subprocess.run(
                [
                    binary,
                    "analyze",
                    "white.rb",
                    "--format",
                    "json",
                    "--profile",
                    "sonar-parity",
                ],
                cwd=root,
                capture_output=True,
                timeout=180,
                check=False,
            )
            require(
                run.returncode == 2 and b"syntax tree" in run.stderr,
                "invalid Ruby scan did not fail closed",
            )
            return {"invalid_input_rejected": True}
        if "sources" in case:
            files = case["sources"]
            for path, content in files.items():
                safe_path(path)
                dest = root / path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(content.encode())
            project_key = case["reference"]["key"]
        else:
            files = case["files"]
            root = pinned_source(case, root, local)
            project_key = case["reference"]["project"]
        report = analyze(root, files, binary)
        return compare(report, case["issues"], project_key, {RULE})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument(
        "--case", action="append", help="Restrict public projects; controls always run."
    )
    parser.add_argument(
        "--local-repositories", type=Path, help="Optional pinned Git checkout map."
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    local = (
        json.loads(args.local_repositories.read_bytes())
        if args.local_repositories
        else {}
    )
    public = manifest("public")
    require(
        not args.case or set(args.case) <= {c["name"] for c in public},
        "unknown public case",
    )
    cases = manifest("controls") + [
        c for c in public if not args.case or c["name"] in args.case
    ]
    results = {}
    for case in cases:
        name = case["name"]
        try:
            result = replay(case, binary, Path(local[name]) if name in local else None)
        except (KeyError, ValueError, OSError, subprocess.SubprocessError) as err:
            results[name] = {"error": str(err)}
            print(f"{name}: {err}", flush=True)
            continue
        results[name] = result
        if result.get("invalid_input_rejected"):
            print(f"{name}: incomplete input rejected", flush=True)
            continue
        print(
            f"{name}: {result['matched_findings']}/{result['reference_findings']} match, "
            f"{result['native_only']} extra, {result['reference_only']} missing",
            flush=True,
        )
    if args.output:
        args.output.write_text(json.dumps(results, indent=2) + "\n")
    if not all(
        r.get("matched") or r.get("invalid_input_rejected") for r in results.values()
    ):
        raise SystemExit(
            "Different Ruby S1192 messages, source ranges or supporting flows."
        )


if __name__ == "__main__":
    main()
