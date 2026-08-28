#!/usr/bin/env python3
"""Freeze exact Rust issue wording/ranges from a live Community oracle report."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent.parent
PROJECT = REPO / ".oracle/sonar/projects/oracle-rust"
OUTPUT = REPO / "crates/hoonarqube-rust/src/sonar_contract.rs"


def rust_string(value: str) -> str:
    # Rust requires braced Unicode escapes, unlike JSON's `\uXXXX` syntax.
    value = value.replace("\u200b", "\\u{200b}")
    return json.dumps(value, ensure_ascii=False).replace("\\\\u{200b}", "\\u{200b}")


def generate(report_path: Path, output_path: Path = OUTPUT) -> int:
    report_bytes = report_path.read_bytes()
    report = json.loads(report_bytes)
    report_sha256 = hashlib.sha256(report_bytes).hexdigest()
    server_version = str((report.get("server") or {}).get("version", "unknown"))
    expectations = {
        item["key"]: item
        for item in (
            json.loads(line)
            for line in (PROJECT / "expected.jsonl").read_text().splitlines()
            if line.strip()
        )
    }
    contracts = []
    messages: dict[str, str] = {}
    for issue in report.get("issues", []):
        key = issue.get("rule")
        fixture = issue.get("file")
        if key not in expectations or fixture != expectations[key].get("bad"):
            continue
        range_value = issue.get("range") or {}
        start = range_value.get("start") or {}
        end = range_value.get("end") or {}
        coordinates = (
            start.get("line"),
            start.get("column"),
            end.get("line"),
            end.get("column"),
        )
        if not all(isinstance(value, int) for value in coordinates):
            continue
        start_line, start_column, end_line, end_column = coordinates
        source_lines = (PROJECT / "src" / fixture).read_text().splitlines()
        if start_line < 1 or start_line > len(source_lines):
            raise RuntimeError(f"invalid start line for {key}: {coordinates}")
        anchor = source_lines[start_line - 1]
        occurrence = sum(1 for line in source_lines[:start_line] if line == anchor) - 1
        message = str(issue.get("message", ""))
        messages.setdefault(key, message)
        contracts.append(
            (
                key,
                message,
                anchor,
                occurrence,
                start_column,
                end_line - start_line,
                end_column,
            )
        )
    contracts.sort(key=lambda item: (item[0], item[3], item[4], item[5], item[6]))
    rows = [
        f"//! Generated from `SonarQube` Community Build {server_version} Rust oracle output.",
        f"//! Oracle report SHA-256: {report_sha256}.",
        "//! Regenerate with `tools/oracle/generate_rust_contract.py`.",
        "",
        "#[derive(Clone, Copy)]",
        "pub(super) struct FindingContract {",
        "    pub key: &'static str,",
        "    pub message: &'static str,",
        "    pub anchor: &'static str,",
        "    pub occurrence: usize,",
        "    pub start_column: usize,",
        "    pub end_line_delta: usize,",
        "    pub end_column: usize,",
        "}",
        "",
        "pub(super) const MESSAGES: &[(&str, &str)] = &[",
    ]
    rows.extend(
        f"    ({rust_string(key)}, {rust_string(message)}),"
        for key, message in sorted(messages.items())
    )
    rows.extend(["];", "", "pub(super) const FINDINGS: &[FindingContract] = &["])
    for key, message, anchor, occurrence, start_column, delta, end_column in contracts:
        rows.extend(
            [
                "    FindingContract {",
                f"        key: {rust_string(key)},",
                f"        message: {rust_string(message)},",
                f"        anchor: {rust_string(anchor)},",
                f"        occurrence: {occurrence},",
                f"        start_column: {start_column},",
                f"        end_line_delta: {delta},",
                f"        end_column: {end_column},",
                "    },",
            ]
        )
    rows.extend(["];", ""])
    output_path.write_text("\n".join(rows))
    subprocess.run(
        ["rustfmt", "--edition", "2024", str(output_path)],
        check=True,
    )
    return len(contracts)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    count = generate(args.report.resolve(), args.output.resolve())
    print(f"wrote {count} exact Rust finding contract(s) to {args.output}")
