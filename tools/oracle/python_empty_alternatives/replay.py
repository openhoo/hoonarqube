"""Check public Python package scans and independently captured regex diagnostics."""

import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from public_contract import git, require, safe_path, stage  # noqa: E402

ALTERNATIVES = "python:S6323"
BOUNDARIES = "python:S5996"


def analyze(binary, root, files):
    proc = subprocess.run(
        [
            binary,
            "analyze",
            *sorted(files),
            "--profile",
            "community-26.11-python-core",
            "--format",
            "json",
        ],
        capture_output=True,
        cwd=root,
        timeout=120,
    )
    report = json.loads(proc.stdout)
    require(
        report["project"]["complete"]
        and len(report["files"]) == len(files)
        and {f["path"] for f in report["files"]} == set(files),
        "native inventory changed",
    )
    require(
        proc.returncode == 2
        and report["partial_rule_selection"]["profile"] == "community-26.11-python-core"
        and report["partial_rule_selection"]["reference_version"] == "26.11.0.134175"
        and report["partial_rule_selection"]["reference_active_rules"] == 232,
        "profile completion and exit disagree",
    )
    return Counter(
        (
            i["rule_key"],
            f["path"],
            *[
                i["range"][pos][key]
                for pos in ("start", "end")
                for key in ("line", "column")
            ],
            i["message"],
        )
        for f in report["files"]
        for i in f["issues"]
    )


def probe(binary):
    source = (HERE / "branches.fixture").read_bytes()
    ref = json.loads((HERE / "expected.json").read_bytes())
    require(
        hashlib.sha256(source).hexdigest() == ref["sha256"]
        and len(ref["locations"]) == 19,
        "wrong probe inputs",
    )
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "branches.py").write_bytes(source)
        hits = analyze(binary, root, ["branches.py"])
        expected = Counter(
            (ALTERNATIVES, "branches.py", *loc) for loc in ref["locations"]
        )
        require(
            Counter({k: v for k, v in hits.items() if k[0] == ALTERNATIVES})
            == expected,
            "independent positive/negative probe positions changed",
        )


def boundary_probes(binary):
    directory = HERE / "boundaries"
    probes = json.loads((directory / "community.json").read_bytes())
    require(
        len({p["analysis"] for p in probes}) == len(probes) == 4
        and sum(p["patterns"] for p in probes) == 134
        and sum(len(p["locations"]) for p in probes) == 75,
        "incomplete independent boundary controls",
    )
    for case in probes:
        fixture = directory / safe_path(case["fixture"])
        source = fixture.read_bytes()
        require(hashlib.sha256(source).hexdigest() == case["sha256"], "wrong probe")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "boundaries.py").write_bytes(source)
            hits = analyze(binary, root, ["boundaries.py"])
        expected = Counter(
            (BOUNDARIES, "boundaries.py", *loc) for loc in case["locations"]
        )
        require(
            Counter({k: v for k, v in hits.items() if k[0] == BOUNDARIES}) == expected,
            f"{fixture.name}: independent boundary ranges or messages differ",
        )


def check_case(binary, case, local):
    safe_path(case["repository"])
    for path in case["files"]:
        safe_path(path)
    with tempfile.TemporaryDirectory() as tmp:
        root = stage(case, Path(tmp), local)
        entries = (
            git(
                local or Path(tmp) / "objects",
                "ls-tree",
                "-rz",
                "--name-only",
                case["commit"],
                "--",
                case["scope"],
            )
            .decode()
            .split("\0")
        )
        require(
            {p for p in entries if p.endswith(".py")} == set(case["files"]),
            "reference inventory differs from pinned source scope",
        )
        native = analyze(binary, root, case["files"])
    ref = Counter(tuple(x) for x in case["issues"])
    require(not case["hotspots"], "hotspots require a separate comparison")
    require(
        {k: v for k, v in native.items() if k[0] in (ALTERNATIVES, BOUNDARIES)}
        == {k: v for k, v in ref.items() if k[0] in (ALTERNATIVES, BOUNDARIES)},
        f"{case['repository']}: S6323/S5996 differs",
    )
    return dict(
        files=len(case["files"]),
        analysis=case["analysis"],
        reference=sum(ref.values()),
        native=sum(native.values()),
        exact=sum((ref & native).values()),
        only_native=sorted((native - ref).elements()),
        only_reference=sorted((ref - native).elements()),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument(
        "--mirrors",
        type=Path,
        help="Optional JSON map of repository to Git checkout at pinned HEAD",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    corpus = json.loads(gzip.decompress((HERE / "community.json.gz").read_bytes()))
    cases = corpus["cases"]
    require(
        corpus["community"] == "26.11.0.134175"
        and corpus["profile"] == "Sonar way core"
        and len({c["github_id"] for c in cases})
        == len({c["analysis"] for c in cases})
        == len(cases)
        == 16
        and sum(len(c["files"]) for c in cases) == 248,
        "incomplete reference cohort",
    )
    mirrors = json.loads(args.mirrors.read_bytes()) if args.mirrors else {}
    probe(binary)
    boundary_probes(binary)
    results = {
        c["repository"]: check_case(
            binary, c, Path(mirrors[c["repository"]]) if args.mirrors else None
        )
        for c in cases
    }
    if args.output:
        args.output.write_text(json.dumps(results, indent=2) + "\n")
    print(
        f"Compared 248 Python files in {len(results)} repositories and 164 regex probes (94 exact target-rule findings)."
    )


if __name__ == "__main__":
    main()
