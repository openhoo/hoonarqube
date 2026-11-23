"""Replay Python S1751 observations on public Git blobs and independently scanned controls."""

import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from public_contract import require, safe_path, stage  # noqa: E402
from public_python_core import analyze, package_findings  # noqa: E402

RULE = "python:S1751"


def target(issues):
    return Counter({k: v for k, v in issues.items() if k[0] == RULE})


def matches(issues, row):
    actual = target(issues)
    expected = Counter(map(tuple, row["locations"]))
    require(
        actual == expected,
        f"{row['analysis']}: extra {actual - expected}, missing {expected - actual}",
    )


def probes(binary):
    rows = json.loads((HERE / "probes.json").read_bytes())
    require(
        len({r["analysis"] for r in rows}) == 6
        and len({r["sha256"] for r in rows}) == 5
        and {r["version"] for r in rows} == {"26.9.0.129388", "26.11.0.134175"},
        "incomplete independent controls",
    )
    for row in rows:
        data = (HERE / safe_path(row["fixture"])).read_bytes()
        require(hashlib.sha256(data).hexdigest() == row["sha256"], "wrong fixture")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "controls.py").write_bytes(data)
            matches(analyze(binary, root, ["controls.py"]), row)


def file_scope(binary, case, local):
    """Replay identical file bytes under both inferred and explicit test scopes."""
    rows = json.loads((HERE / "file-scope.json").read_bytes())
    require(
        {row["mode"] for row in rows} == {"configured", "inferred"}
        and len({row["analysis"] for row in rows}) == len(rows) == 2,
        "scope controls missing",
    )
    with tempfile.TemporaryDirectory() as temp:
        source = stage(case, Path(temp), local)
        data = (source / case["scope"]).read_bytes()
        for row in rows:
            require(
                hashlib.sha256(data).hexdigest() == row["sha256"],
                "wrong source for file scope",
            )
            root = Path(temp) / row["mode"]
            for name in row["paths"]:
                path = root / safe_path(name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            configured = row["mode"] == "configured"
            require(
                len(row["paths"]) == (4 if configured else 9)
                and len(row["locations"]) == (2 if configured else 3),
                "incomplete path matrix",
            )
            flags = ["--test-include", "checks/**"] if configured else []
            matches(analyze(binary, root, row["paths"], cli_options=flags), row)
            if configured:
                # A regular file under app/tests/ keeps its Source classification
                # in both scans, even though its effective Python scope changes.
                cache = ["--cache-dir", str(Path(temp) / "cache")]
                inferred = analyze(binary, root, row["paths"])
                require(
                    analyze(binary, root, row["paths"], cli_options=cache) == inferred,
                    "cold cached scan differs",
                )
                matches(
                    analyze(binary, root, row["paths"], cli_options=cache + flags), row
                )
                require(
                    analyze(binary, root, row["paths"], cli_options=cache) == inferred,
                    "explicit scope contaminated the inferred cache",
                )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument(
        "--mirrors",
        type=Path,
        help="Optional map from repository to pinned local Git checkout.",
    )
    args = p.parse_args()
    binary = args.binary.resolve(strict=True)
    mirrors = json.loads(args.mirrors.read_bytes()) if args.mirrors else None
    cases = json.loads(gzip.decompress((HERE / "public.json.gz").read_bytes()))
    require(
        len({c["github_id"] for c in cases}) == 9
        and len({c["analysis"] for c in cases}) == len(cases) == 10
        and sum(len(c["files"]) for c in cases) == 395
        and all(
            c["profile"] == "Sonar way core" and c["version"] == "26.11.0.134175"
            for c in cases
        ),
        "incomplete public scope",
    )
    probes(binary)
    for case in cases:
        local = Path(mirrors[case["repository"]]) if mirrors else None
        matches(package_findings(binary, case, local), case)
        if case["scope"] == "tests/data/cases/fmtskip10.py":
            file_scope(binary, case, local)
    print(
        "S1751: verified nine public package inventories, Black's formatter fixture, and independent flow and scope controls."
    )


if __name__ == "__main__":
    main()
