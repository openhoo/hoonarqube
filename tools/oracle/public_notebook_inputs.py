"""Replay notebook scope and one source-location comparison from three public projects."""

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

from community_new_duplication import git
from public_coverage_gate_replay import check
from public_empty_inventory_gate import select


CAPTURE = Path(__file__).with_name("fixtures") / "notebook-inputs-2611.json"
REPOS = {"jupyter/nbdime", "jupyter-widgets/ipywidgets", "jupyter/nbclassic"}


def scan(root, binary, paths, *opts):
    proc = subprocess.run(
        [
            binary,
            "analyze",
            *paths,
            "--profile",
            "sonar-parity",
            "--format",
            "json",
            *opts,
        ],
        cwd=root,
        capture_output=True,
        check=False,
        timeout=60,
    )
    return proc.returncode, json.loads(proc.stdout)


def check_scope(root, binary, case, policy):
    files = {k: v["sha256"] for k, v in case["files"].items()}
    control = set(case["control"])
    mixed = case["mixed_reference"]
    (cond,) = mixed["gate"]["conditions"]
    check(
        not mixed["policy"]["default"]
        and mixed["gate"]["status"] == "OK"
        and not mixed["gate"]["ignoredConditions"]
        and cond["metricKey"] == "duplicated_lines"
        and cond["comparator"] == "GT"
        and cond["errorThreshold"] == cond["actualValue"] == "0"
        and mixed["project_metrics"]["duplicated_lines"] == "0"
        and int(mixed["control_metrics"]["ncloc"]) > 0,
        "mixed reference lacks its assigned decision",
    )
    select(root, case, files | case["control"])
    for paths, exclude, measured, code in (
        (sorted(files), False, set(), 2),
        (["."], False, control, 2),
        (["."], True, control, 0),
    ):
        opts = ["--quality-gate", str(policy)]
        if exclude:
            opts += ["--exclude", "**/*.ipynb"]
        rc, report = scan(root, binary, paths, *opts)
        gate = report["assessment"]["gate"]
        scopes = {Path(f["path"]).as_posix(): f for f in report["project"]["files"]}
        expected = "excluded" if exclude else "unsupported"
        check(
            rc == code
            and gate["status"] == ("pass" if exclude else "unavailable")
            and gate["conditions"][0]["actual"] == (0 if exclude else None)
            and report["project"]["complete"] == exclude
            and {Path(f["path"]).as_posix() for f in report["files"]} == measured
            and set(scopes) == set(files) | measured
            and all(
                scopes[p]["status"] == expected and scopes[p].get("metrics") is None
                for p in files
            ),
            f"{root.name}: incomplete or excluded input changed its gate",
        )


def projection(notebook):
    """Join code cells as inert text. Map sample rows back to cell and source row."""
    projected = ""
    mapping = {}
    for index, cell in enumerate(notebook["cells"]):
        if cell["cell_type"] != "code":
            continue
        source = "".join(cell["source"])
        if projected:
            projected += "\n\n"
        first = projected.count("\n") + 1
        for offset, line in enumerate(source.splitlines()):
            mapping[first + offset] = (index, offset, line)
        projected += source
    return projected, mapping


def compare_projection(root, plain, binary, path, expected):
    raw = (root / path).read_text(encoding="utf-8")
    notebook = json.loads(raw)
    check(notebook["nbformat"] == 4, "unexpected notebook version")
    src, mapping = projection(notebook)
    check(
        raw.count("\n") + 1 == int(expected["metrics"]["lines"])
        and sum(c["cell_type"] == "code" for c in notebook["cells"])
        == expected["code_cells"]
        and "duplicated_lines" not in expected["metrics"],
        f"{path}: changed physical or measured scope",
    )
    if not expected["code_cells"]:
        check(
            expected["metrics"].get("ncloc") == "0" and not expected["issues"],
            f"{path}: invalid code-free control",
        )
    target = plain / "projection.py"
    target.write_text(src, encoding="utf-8")
    rc, result = scan(plain, binary, [target.name])
    check(
        result["project"]["complete"] == expected["projected_python_complete"]
        and rc == (0 if expected["projected_python_complete"] else 2),
        f"{path}: projected parse completeness changed",
    )
    native = [
        x
        for f in result["files"]
        for x in f["issues"]
        if x["rule_key"] == "python:S7502"
    ]
    reference = expected["issues"]
    check(
        all(x["rule"] == "ipython:S7502" for x in reference),
        "unexpected reference rule",
    )
    check(len(native) == len(reference), f"{path}: projected result count changed")
    for own, ref in zip(native, reference, strict=True):
        loc = ref["textRange"]
        span = own["range"]
        cell, row, code_line = mapping[span["start"]["line"]]
        # This captured positive has one JSON string per source line. Prove the
        # correspondence on this exact blob; never use a string search as a
        # general location mapper for edited or compact JSON.
        line = raw.splitlines()[loc["startLine"] - 1]
        original = notebook["cells"][cell]["source"][row]
        check(
            loc["startLine"] == loc["endLine"]
            and json.loads(line.strip().removesuffix(",")) == original
            and code_line == original.rstrip("\n")
            and raw.splitlines().count(line) == 1,
            f"{path}: original source location is ambiguous",
        )
        highlight = line[loc["startOffset"] : loc["endOffset"]]
        own_text = code_line[span["start"]["column"] : span["end"]["column"]]
        check(
            highlight == ref["raw_highlight"] == "asyncio.ensure_future"
            and own_text == "asyncio.ensure_future(f())"
            and not result["project"]["complete"],
            "the two engines no longer have the recorded range/measurement difference",
        )
    return len(native)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("--local-sources", type=Path)
    args = p.parse_args()
    binary = args.binary.resolve(strict=True)
    captures = json.loads(CAPTURE.read_bytes())
    check(
        captures["community"] == "26.11.0.134175"
        and captures["profile"]
        == {"language": "ipynb", "name": "Sonar way core", "active": 230}
        and {case["repository"] for case in captures["projects"]} == REPOS,
        "unexpected reference capture",
    )
    total = positives = missing = 0
    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        plain = work / "projection"
        plain.mkdir()
        policy = work / "gate.json"
        policy.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "conditions": [
                        {
                            "scope": "overall",
                            "metric": "duplicated_lines",
                            "operator": "lte",
                            "threshold": 0,
                        }
                    ],
                }
            )
        )
        for case in captures["projects"]:
            repo = case["repository"]
            root = work / repo.split("/")[1]
            git(work, "init", "-q", str(root))
            source = (
                str((args.local_sources / root.name).resolve())
                if args.local_sources
                else f"https://github.com/{repo}.git"
            )
            git(root, "fetch", "-q", "--no-tags", "--depth=1", source, case["commit"])
            check_scope(root, binary, case, policy)
            for path, expected in case["files"].items():
                positives += compare_projection(root, plain, binary, path, expected)
                total += 1
                missing += "ncloc" not in expected["metrics"]
            check(
                case["project_metrics"]["duplicated_lines"] == "0",
                "project reference changed",
            )
            print(
                f"{repo} {case['commit']}: explicit and mixed gates unavailable; exclusion passes"
            )
    check((total, positives, missing) == (21, 1, 1), "different qualification cohort")
    print(
        "21 pinned notebooks; one projected S7502 and 20 silent controls; one missing ncloc."
    )


if __name__ == "__main__":
    main()
