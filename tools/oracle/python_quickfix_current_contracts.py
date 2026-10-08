#!/usr/bin/env python3
"""Qualify current Python quickfix contracts without rewriting historical evidence."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def issues(report: dict) -> list[dict]:
    return [issue for file in report["files"] for issue in file.get("issues", [])]


def counts(report: dict) -> Counter:
    return Counter(issue["rule_key"] for issue in issues(report))


def invoke(command: list[str], folder: Path, label: str) -> tuple[int, dict]:
    completed = subprocess.run(command, capture_output=True, timeout=90, check=False)
    (folder / (label + ".stdout")).write_bytes(completed.stdout)
    (folder / (label + ".stderr")).write_bytes(completed.stderr)
    write_json(
        folder / (label + ".invocation.json"),
        {"command": command, "exit_code": completed.returncode},
    )
    return completed.returncode, json.loads(completed.stdout)


def projected(source: str, edits: list[dict]) -> str:
    # These contracts intentionally use ASCII: their JSON columns are byte
    # offsets as well as UTF-16 columns, avoiding ambiguous span conversion.
    assert source.isascii(), "fixture must have unambiguous ASCII columns"
    lines = source.splitlines(keepends=True)
    starts = [0]
    for line in lines:
        starts.append(starts[-1] + len(line))

    def offset(position: dict) -> int:
        return starts[position["line"] - 1] + position["column"]

    for edit in sorted(
        edits, key=lambda edit: offset(edit["range"]["start"]), reverse=True
    ):
        source = (
            source[: offset(edit["range"]["start"])]
            + edit["replacement"]
            + source[offset(edit["range"]["end"]) :]
        )
    return source


def runtime(source: str) -> dict:
    result = subprocess.run(
        [sys.executable, "-c", source], capture_output=True, timeout=15, check=False
    )
    return {
        "exit_code": result.returncode,
        "stdout": result.stdout.decode(),
        "exception": result.stderr.decode().splitlines()[-1:],
    }


def qualify_truth_runtime(source: str, projection: str, folder: Path) -> dict:
    original_runtime, projected_runtime = runtime(source), runtime(projection)
    write_json(
        folder / "runtime.json",
        {"original": original_runtime, "projected": projected_runtime},
    )
    assert original_runtime == projected_runtime, (
        "projection changes truth effects or exceptions"
    )
    # The historical upstream projection drops truth testing. Demonstrate
    # the difference on the same executable fixture as the native action.
    unsafe = projection.replace("bool((a))\n", "")
    unsafe_runtime = runtime(unsafe)
    write_json(folder / "unsafe-upstream-runtime.json", unsafe_runtime)
    assert unsafe_runtime != original_runtime, (
        "truth-effect control failed to distinguish unsafe projection"
    )
    return {"runtime_equivalent": True, "upstream_projection_changes_runtime": True}


def qualify(binary: Path, case: dict, folder: Path) -> dict:
    folder.mkdir(parents=True, exist_ok=True)
    fixture = folder / "case.py"
    source = case["source"]
    fixture.write_text(source)
    result = {
        "name": case["name"],
        "rule": case["rule"],
        "mode": case["mode"],
        "profile": case["profile"],
        "reason": case["reason"],
        "failures": [],
    }
    failures = result["failures"]
    try:
        analyze = [
            str(binary),
            "analyze",
            "--profile",
            case["profile"],
            "--format",
            "json",
        ]
        code, before = invoke([*analyze, str(fixture)], folder, "before")
        assert code == 0, "initial analyze failed"
        target = [
            issue for issue in issues(before) if issue["rule_key"] == case["rule"]
        ]
        actions = [
            alternative
            for issue in target
            for alternative in issue.get("alternatives", [])
            if alternative["id"] == case["action"]
        ]
        result["initial_target_count"] = len(target)
        if case["mode"] == "no_action":
            assert len(target) == case.get("target_count", 0) and not actions, (
                "control unexpectedly actionable"
            )
        else:
            assert len(target) == 1 and len(actions) == 1, (
                "expected exactly one actionable finding"
            )
            projection = projected(source, actions[0]["fix"]["edits"])
            (folder / "projected.py").write_text(projection)
            assert projection == case["projection"], (
                "projection differs from current contract"
            )
            if case.get("runtime"):
                result.update(qualify_truth_runtime(source, projection, folder))
            if case.get("regression_guard"):
                code, projection_report = invoke(
                    [*analyze, str(folder / "projected.py")],
                    folder,
                    "projection-analyze",
                )
                assert code == 0, "projection analyze failed"
                guard = case["regression_guard"]
                increase = (
                    counts(projection_report)[guard["rule"]]
                    - counts(before)[guard["rule"]]
                )
                result["guard_increase"] = {guard["rule"]: increase}
                assert increase == guard["increase"], (
                    "regression guard differs from contract"
                )
            fix = [
                str(binary),
                "--json",
                "fix",
                "--suggestion",
                case["rule"] + "=" + case["action"],
                "--diff",
                "--apply",
            ]
            if case["profile"] != "sonar-parity":
                fix.extend(["--profile", case["profile"]])
            code, applied = invoke([*fix, str(fixture)], folder, "apply")
            if case["mode"] == "safety_refusal":
                assert (
                    code == 1
                    and applied["verified"] == 0
                    and applied["unverified"] == 1
                ), "unsafe apply was not refused"
                assert not any(file["written"] for file in applied["files"]), (
                    "refused apply wrote a file"
                )
                assert fixture.read_text() == source, "refusal changed original bytes"
            else:
                assert (
                    code == 0
                    and applied["verified"] == 1
                    and applied["unverified"] == 0
                ), "positive apply not verified"
                assert fixture.read_text() == projection, (
                    "written source differs from projection"
                )
                code, after = invoke([*analyze, str(fixture)], folder, "after")
                assert code == 0 and counts(after)[case["rule"]] == 0, (
                    "target was not eliminated"
                )
        result["status"] = "current_contract_pass"
    except (AssertionError, KeyError, ValueError, subprocess.TimeoutExpired) as error:
        failures.append(str(error))
        result["status"] = "current_contract_fail"
    write_json(folder / "result.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--historical-result", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve()
    manifest = Path(__file__).with_name("python-quickfix-current-contracts.json")
    contract = json.loads(manifest.read_text())
    historical = json.loads(args.historical_result.read_text())
    rows = historical.get("applications", [])
    selected_rules = {case["rule"] for case in contract["cases"]}
    historical_rows = [row for row in rows if row.get("rule_key") in selected_rules]
    if not selected_rules.issubset({row.get("rule_key") for row in historical_rows}):
        parser.error("historical result does not contain every owned rule")
    args.output.mkdir(parents=True, exist_ok=True)
    result = {
        "schema_version": 1,
        "binary": {"path": str(binary), "sha256": sha256(binary)},
        "current_contract": {"path": str(manifest), "sha256": sha256(manifest)},
        "historical_result": {
            "path": str(args.historical_result.resolve()),
            "sha256": sha256(args.historical_result),
            "summary": historical.get("summary"),
            "owned_rows_verbatim": historical_rows,
        },
        "historical_policy": contract["historical_policy"],
        "cases": [
            qualify(binary, case, args.output / case["name"])
            for case in contract["cases"]
        ],
    }
    result["ok"] = all(
        case["status"] == "current_contract_pass" for case in result["cases"]
    )
    result["summary"] = dict(Counter(case["status"] for case in result["cases"]))
    write_json(args.output / "result.json", result)
    print(json.dumps({"ok": result["ok"], "summary": result["summary"]}))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
