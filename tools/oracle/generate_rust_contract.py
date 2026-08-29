#!/usr/bin/env python3
"""Freeze exact Rust issue wording/ranges from a live Community oracle report."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from parity import read_json, read_jsonl, sonar_findings, write_text_atomic


REPO = Path(__file__).resolve().parent.parent.parent
PROJECT = REPO / ".oracle/sonar/projects/oracle-rust"
OUTPUT = REPO / "crates/hoonarqube-rust/src/sonar_contract.rs"
RUSTFMT_TIMEOUT_SECONDS = 60


def rust_string(value: str) -> str:
    # Rust requires braced Unicode escapes, unlike JSON's `\uXXXX` syntax.
    value = value.replace("\u200b", "\\u{200b}")
    return json.dumps(value, ensure_ascii=False).replace("\\\\u{200b}", "\\u{200b}")


def load_expectations():
    expectations = {}
    for index, item in enumerate(read_jsonl(PROJECT / "expected.jsonl")):
        if not isinstance(item, dict):
            raise ValueError(f"Rust expectation {index} must be an object")
        key = item.get("key")
        bad = item.get("bad")
        if not isinstance(key, str) or not key:
            raise ValueError(f"Rust expectation {index} key must be a string")
        if key in expectations:
            raise ValueError(f"duplicate Rust expectation key: {key}")
        if not isinstance(bad, str) or not bad:
            raise ValueError(f"{key}: missing bad fixture")
        expectations[key] = item
    return expectations


def report_metadata(report_path: Path):
    report_bytes = report_path.read_bytes()
    report = read_json(report_path)
    if report.get("project") != "oracle-rust":
        raise ValueError(
            f"Rust contract report project must be 'oracle-rust'; "
            f"got {report.get('project')!r}"
        )
    server = report.get("server")
    server_version = server.get("version") if isinstance(server, dict) else None
    if not isinstance(server_version, str) or not server_version:
        raise ValueError("Rust contract report lacks SonarQube server version")
    return (
        sonar_findings(report),
        server_version,
        hashlib.sha256(report_bytes).hexdigest(),
    )


def finding_contracts(findings, expectations):
    contracts = []
    messages: dict[str, str] = {}
    for finding in findings:
        key, fixture, message, start_line, start_column, end_line, end_column = finding
        if key not in expectations:
            raise ValueError(f"Rust oracle issue uses unknown rule: {key}")
        if fixture != expectations[key].get("bad"):
            continue
        coordinates = (start_line, start_column, end_line, end_column)
        if not all(isinstance(value, int) for value in coordinates):
            raise ValueError(f"file-level Rust contract finding for {key}")
        assert all(isinstance(value, int) for value in coordinates)
        source_lines = (PROJECT / "src" / fixture).read_text().splitlines()
        if start_line < 1 or start_line > len(source_lines):
            raise RuntimeError(f"invalid start line for {key}: {coordinates}")
        anchor = source_lines[start_line - 1]
        occurrence = sum(1 for line in source_lines[:start_line] if line == anchor) - 1
        assert isinstance(message, str)
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
    return contracts, messages


def render_contract(server_version, report_sha256, contracts, messages):
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
    return "\n".join(rows)


def format_contract(rendered: str, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="rust-contract-", dir=output_path.parent
    ) as directory:
        candidate = Path(directory) / "sonar_contract.rs"
        candidate.write_text(rendered)
        try:
            subprocess.run(
                ["rustfmt", "--edition", "2024", str(candidate)],
                check=True,
                capture_output=True,
                text=True,
                timeout=RUSTFMT_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("rustfmt timed out") from error
        except subprocess.CalledProcessError as error:
            detail = (error.stdout + error.stderr).strip()
            raise RuntimeError(f"rustfmt failed: {detail[-2000:]}") from error
        write_text_atomic(output_path, candidate.read_text())


def generate(report_path: Path, output_path: Path = OUTPUT) -> int:
    findings, server_version, report_sha256 = report_metadata(report_path)
    contracts, messages = finding_contracts(findings, load_expectations())
    rendered = render_contract(server_version, report_sha256, contracts, messages)
    format_contract(rendered, output_path)
    return len(contracts)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    count = generate(args.report.resolve(), args.output.resolve())
    print(f"wrote {count} exact Rust finding contract(s) to {args.output}")
