#!/usr/bin/env python3
"""Generate a SonarQube-compatible Clippy report for Rust oracle fixtures.

SonarQube's Rust analyzer implements two native rules and imports the other
Community rules from Cargo's JSON-formatted Clippy diagnostics.  This module
runs every fixture with only its mapped lint enabled, fails closed when a bad
fixture does not emit that lint or a good fixture does, and combines the bad
diagnostics into one report for the scanner.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import zipfile
from pathlib import Path

from parity import read_jsonl, write_text_atomic


NATIVE_RULES = frozenset({"rust:S2260", "rust:S3776"})

CLIPPY_LINTS = {
    "rust:S106": "clippy::print_stdout",
    "rust:S107": "clippy::too_many_arguments",
    "rust:S1116": "clippy::unnecessary_semicolon",
    "rust:S126": "clippy::else_if_without_else",
    "rust:S1488": "clippy::let_and_return",
    "rust:S1612": "clippy::redundant_closure_for_method_calls",
    "rust:S1656": "clippy::self_assignment",
    "rust:S1751": "clippy::never_loop",
    "rust:S1764": "clippy::eq_op",
    "rust:S1858": "clippy::string_to_string",
    "rust:S1862": "clippy::ifs_same_cond",
    "rust:S2148": "clippy::unreadable_literal",
    "rust:S2185": "clippy::erasing_op",
    "rust:S2193": "clippy::while_float",
    "rust:S2198": "clippy::absurd_extreme_comparisons",
    "rust:S2208": "clippy::wildcard_imports",
    "rust:S2437": "clippy::ineffective_bit_mask",
    "rust:S2479": "clippy::invisible_characters",
    "rust:S2589": "clippy::overly_complex_bool_expr",
    "rust:S3498": "clippy::redundant_field_names",
    "rust:S3723": "clippy::possible_missing_comma",
    "rust:S3807": "clippy::invalid_null_ptr_usage",
    "rust:S4275": "clippy::misnamed_getters",
    "rust:S4325": "clippy::unnecessary_cast",
    "rust:S4962": "clippy::zero_ptr",
    "rust:S5856": "clippy::invalid_regex",
    "rust:S6164": "clippy::approx_constant",
    "rust:S6466": "clippy::out_of_bounds_indexing",
    "rust:S6913": "clippy::min_max",
    "rust:S7089": "clippy::vec_init_then_push",
    "rust:S7200": "clippy::vec_resize_to_zero",
    "rust:S7411": "clippy::branches_sharing_code",
    "rust:S7412": "clippy::zst_offset",
    "rust:S7413": "clippy::async_yields_async",
    "rust:S7414": "clippy::wrong_transmute",
    "rust:S7415": "clippy::while_immutable_condition",
    "rust:S7417": "clippy::derive_ord_xor_partial_ord",
    "rust:S7418": "clippy::useless_attribute",
    "rust:S7419": "clippy::unused_io_amount",
    "rust:S7420": "clippy::unsound_collection_transmute",
    "rust:S7421": "clippy::unit_return_expecting_ord",
    "rust:S7422": "clippy::unit_hash",
    "rust:S7423": "clippy::unit_cmp",
    "rust:S7424": "clippy::derived_hash_with_manual_eq",
    "rust:S7425": "clippy::uninit_assumed_init",
    "rust:S7426": "clippy::enum_clike_unportable_variant",
    "rust:S7427": "clippy::transmuting_null",
    "rust:S7428": "clippy::match_str_case_mismatch",
    "rust:S7429": "clippy::transmute_null_to_fn",
    "rust:S7430": "clippy::suspicious_splitn",
    "rust:S7431": "clippy::size_of_in_element_count",
    "rust:S7432": "clippy::reversed_empty_ranges",
    "rust:S7433": "clippy::cast_slice_different_sizes",
    "rust:S7436": "clippy::redundant_comparisons",
    "rust:S7437": "clippy::almost_swapped",
    "rust:S7438": "clippy::bad_bit_mask",
    "rust:S7439": "clippy::impossible_comparisons",
    "rust:S7440": "clippy::recursive_format_impl",
    "rust:S7441": "clippy::read_line_without_trim",
    "rust:S7442": "clippy::panicking_unwrap",
    "rust:S7443": "clippy::eager_transmute",
    "rust:S7444": "clippy::panicking_overflow_checks",
    "rust:S7445": "clippy::option_env_unwrap",
    "rust:S7446": "clippy::not_unsafe_ptr_arg_deref",
    "rust:S7447": "clippy::nonsensical_open_options",
    "rust:S7448": "clippy::non_octal_unix_permissions",
    "rust:S7449": "clippy::inline_fn_without_body",
    "rust:S7450": "let_underscore_lock",
    "rust:S7451": "clippy::modulo_one",
    "rust:S7453": "clippy::mut_from_ref",
    "rust:S7454": "clippy::mistyped_literal_suffixes",
    "rust:S7455": "clippy::iter_next_loop",
    "rust:S7456": "clippy::iter_skip_zero",
    "rust:S7457": "clippy::iterator_step_by_zero",
    "rust:S7458": "clippy::inherent_to_string_shadow_display",
    "rust:S7459": "clippy::uninit_vec",
    "rust:S7460": "clippy::serde_api_misuse",
    "rust:S7461": "clippy::impl_hash_borrow_with_str_and_bytes",
    "rust:S7462": "clippy::mem_replace_with_uninit",
    "rust:S7463": "clippy::inverted_saturating_sub",
    "rust:S7464": "clippy::infinite_iter",
    "rust:S905": "clippy::no_effect",
    "rust:S920": "clippy::match_bool",
}

# Clippy occasionally removes a lint while SonarQube keeps accepting its
# historical diagnostic code. Use the direct successor to validate behavior,
# then restore the code expected by SonarQube's importer.
RUN_LINTS = {
    "rust:S1858": "clippy::implicit_clone",
    "rust:S3807": "invalid_null_arguments",
}

# Boundaries where the analyzer plugin and the current Rust toolchain cannot
# exchange a native rust:S diagnostic. Keep the reason text exact so an oracle
# row cannot silently acquire or retain an unverified exemption.
UPSTREAM_BOUNDARIES = {
    "rust:S1858": {
        "plugin_lint": "clippy::string_to_string",
        "runtime_lint": "clippy::implicit_clone",
        "failure": "lint-id-mismatch",
        "reason": "SonarQube requests removed Clippy lint string_to_string",
    },
    "rust:S3723": {
        "plugin_lint": "clippy::possible_missing_comma",
        "runtime_lint": "clippy::possible_missing_comma",
        "failure": "zero-width-primary-span",
        "reason": "SonarQube rejects Clippy possible_missing_comma zero-width span",
    },
    "rust:S3807": {
        "plugin_lint": "clippy::invalid_null_ptr_usage",
        "runtime_lint": "invalid_null_arguments",
        "failure": "lint-id-mismatch",
        "reason": "SonarQube requests renamed Clippy lint invalid_null_ptr_usage",
    },
    "rust:S4275": {
        "plugin_lint": "clippy::misnamed_getter",
        "runtime_lint": "clippy::misnamed_getters",
        "failure": "lint-id-mismatch",
        "reason": "SonarQube requests nonexistent singular Clippy lint misnamed_getter",
    },
    "rust:S7450": {
        "plugin_lint": "clippy::let_underscore_lock",
        "runtime_lint": "let_underscore_lock",
        "failure": "lint-id-mismatch",
        "reason": "SonarQube requests Clippy namespace for rustc lint let_underscore_lock",
    },
}
FIXTURE_TIMEOUT_SECONDS = 300


def expectations(project_dir: Path) -> list[dict[str, object]]:
    path = project_dir / "expected.jsonl"
    rows = read_jsonl(path)
    seen = set()
    for index, item in enumerate(rows):
        if not isinstance(item, dict):
            raise RuntimeError(f"Rust expectation {index} must be an object")
        key = item.get("key")
        if not isinstance(key, str) or not key:
            raise RuntimeError(f"Rust expectation {index} key must be a string")
        if key in seen:
            raise RuntimeError(f"duplicate Rust expectation key: {key}")
        seen.add(key)
        bad = item.get("bad")
        good = item.get("good") or (
            bad.replace("_bad", "_good") if isinstance(bad, str) else None
        )
        if not isinstance(bad, str) or not bad:
            raise RuntimeError(f"{key}: missing bad fixture")
        if not isinstance(good, str) or not good or good == bad:
            raise RuntimeError(f"{key}: missing good fixture")
    return rows


def validate_mapping(project_dir: Path) -> None:
    items = expectations(project_dir)
    keys = {str(item["key"]) for item in items}
    mapped = set(CLIPPY_LINTS) | set(NATIVE_RULES)
    if keys != mapped:
        missing = sorted(keys - mapped)
        extra = sorted(mapped - keys)
        raise RuntimeError(
            f"Rust Clippy mapping mismatch: missing={missing}, extra={extra}"
        )
    reasons = {
        str(item["key"]): item["upstream_unverified"]
        for item in items
        if "upstream_unverified" in item
    }
    expected_reasons = {
        key: boundary["reason"] for key, boundary in UPSTREAM_BOUNDARIES.items()
    }
    if reasons != expected_reasons:
        raise RuntimeError(
            "Rust upstream boundary mismatch: "
            f"expected={expected_reasons}, actual={reasons}"
        )


def diagnostic_code(record: dict[str, object]) -> str | None:
    if record.get("reason") != "compiler-message":
        return None
    message = record.get("message")
    if not isinstance(message, dict):
        return None
    code = message.get("code")
    if not isinstance(code, dict):
        return None
    value = code.get("code")
    return value if isinstance(value, str) else None


def plugin_rule_lints(plugin_jar: Path) -> dict[str, str]:
    """Read native Rust rule-to-Clippy mappings from a Sonar plugin JAR."""
    resource = "org/sonar/l10n/rust/rules/clippy/rules.json"
    try:
        with zipfile.ZipFile(plugin_jar) as archive:
            payload = json.loads(archive.read(resource))
    except (OSError, KeyError, zipfile.BadZipFile, json.JSONDecodeError) as error:
        raise RuntimeError(
            f"cannot read {resource} from {plugin_jar}: {error}"
        ) from error
    if not isinstance(payload, list):
        raise RuntimeError(f"{plugin_jar}: Clippy rules payload must be an array")
    mappings: dict[str, str] = {}
    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            raise RuntimeError(f"{plugin_jar}: Clippy rule {index} must be an object")
        rule = item.get("ruleKey")
        lint = item.get("lintId")
        if rule is None:
            continue
        if not isinstance(rule, str) or not isinstance(lint, str):
            raise RuntimeError(f"{plugin_jar}: Clippy rule {index} has invalid IDs")
        key = f"rust:{rule}"
        if key in mappings:
            raise RuntimeError(f"{plugin_jar}: duplicate Clippy mapping for {key}")
        mappings[key] = lint
    return mappings


def primary_span(record: dict[str, object]) -> dict[str, object] | None:
    message = record.get("message")
    if not isinstance(message, dict):
        return None
    spans = message.get("spans")
    if not isinstance(spans, list):
        return None
    return next(
        (
            span
            for span in spans
            if isinstance(span, dict) and span.get("is_primary") is True
        ),
        None,
    )


def _tool_version(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(f"cannot query {' '.join(command)}: {error}") from error
    return result.stdout.strip()


def verify_upstream_boundaries(
    project_dir: Path, plugin_jar: Path
) -> dict[str, object]:
    """Prove every upstream exemption against plugin metadata and live Clippy."""
    validate_mapping(project_dir)
    plugin_lints = plugin_rule_lints(plugin_jar)
    evidence = []
    with tempfile.TemporaryDirectory(prefix="rust-upstream-oracle-") as directory:
        temp = Path(directory)
        manifest = temp / "Cargo.toml"
        target = temp / "target"
        for item in expectations(project_dir):
            key = str(item["key"])
            boundary = UPSTREAM_BOUNDARIES.get(key)
            if boundary is None:
                continue
            plugin_lint = plugin_lints.get(key)
            if plugin_lint != boundary["plugin_lint"]:
                raise RuntimeError(
                    f"{key}: plugin lint drifted: expected {boundary['plugin_lint']}, "
                    f"got {plugin_lint}"
                )
            runtime_lint = str(boundary["runtime_lint"])
            bad_name, good_name = (pair[0] for pair in _fixture_pairs(item))
            bad_records = run_fixture(
                project_dir / "src" / bad_name, runtime_lint, manifest, target
            )
            good_records = run_fixture(
                project_dir / "src" / good_name, runtime_lint, manifest, target
            )
            bad_matches = [
                record
                for record in bad_records
                if diagnostic_code(record) == runtime_lint
            ]
            good_matches = [
                record
                for record in good_records
                if diagnostic_code(record) == runtime_lint
            ]
            if len(bad_matches) != 1 or good_matches:
                raise RuntimeError(
                    f"{key}: expected one bad and zero good {runtime_lint} diagnostics, "
                    f"got {len(bad_matches)} and {len(good_matches)}"
                )
            span = primary_span(bad_matches[0])
            if span is None:
                raise RuntimeError(f"{key}: runtime diagnostic lacks a primary span")
            failure = boundary["failure"]
            if failure == "lint-id-mismatch":
                if plugin_lint == runtime_lint:
                    raise RuntimeError(f"{key}: lint IDs now agree; remove exemption")
            elif failure == "zero-width-primary-span":
                start = (span.get("line_start"), span.get("column_start"))
                end = (span.get("line_end"), span.get("column_end"))
                if plugin_lint != runtime_lint or start != end:
                    raise RuntimeError(
                        f"{key}: zero-width boundary no longer holds: "
                        f"plugin={plugin_lint}, runtime={runtime_lint}, span={start}..{end}"
                    )
            else:
                raise RuntimeError(f"{key}: unknown boundary type {failure}")
            evidence.append(
                {
                    "key": key,
                    "failure": failure,
                    "plugin_lint": plugin_lint,
                    "runtime_lint": runtime_lint,
                    "primary_span": {
                        name: span.get(name)
                        for name in (
                            "file_name",
                            "line_start",
                            "column_start",
                            "line_end",
                            "column_end",
                        )
                    },
                    "reason": boundary["reason"],
                }
            )
    return {
        "schema_version": 1,
        "plugin": str(plugin_jar),
        "plugin_sha256": hashlib.sha256(plugin_jar.read_bytes()).hexdigest(),
        "rustc": _tool_version(["rustc", "--version"]),
        "clippy": _tool_version(["cargo", "clippy", "--version"]),
        "boundaries": evidence,
    }


def rewrite_span_paths(value: object, fixture_name: str) -> None:
    if isinstance(value, dict):
        if "file_name" in value:
            value["file_name"] = f"src/{fixture_name}"
        for child in value.values():
            rewrite_span_paths(child, fixture_name)
    elif isinstance(value, list):
        for child in value:
            rewrite_span_paths(child, fixture_name)


def run_fixture(
    fixture: Path,
    lint: str,
    manifest: Path,
    cargo_target_dir: Path,
) -> list[dict[str, object]]:
    manifest.write_text(
        "\n".join(
            [
                "[package]",
                'name = "hoonarqube-rust-oracle-fixture"',
                'version = "0.0.0"',
                'edition = "2024"',
                "",
                "[[bin]]",
                'name = "hoonarqube-rust-oracle-fixture"',
                f"path = {json.dumps(str(fixture.resolve()))}",
                "",
                "[dependencies]",
                'regex = "1"',
                'serde = "1"',
                "",
            ]
        )
    )
    env = dict(os.environ)
    env["CARGO_TARGET_DIR"] = str(cargo_target_dir)
    try:
        result = subprocess.run(
            [
                "cargo",
                "clippy",
                "--quiet",
                "--message-format=json",
                "--manifest-path",
                str(manifest),
                "--",
                "-W",
                lint,
                "--cap-lints",
                "warn",
            ],
            capture_output=True,
            text=True,
            env=env,
            timeout=FIXTURE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"{fixture.name} Clippy run timed out") from error
    records = []
    for line_number, line in enumerate(result.stdout.splitlines(), 1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise RuntimeError(
                f"{fixture.name} emitted malformed Cargo JSON at line {line_number}"
            ) from error
        if not isinstance(record, dict):
            raise RuntimeError(
                f"{fixture.name} emitted non-object Cargo JSON at line {line_number}"
            )
        records.append(record)
    errors = [
        record
        for record in records
        if isinstance(record.get("message"), dict)
        and record["message"].get("level") == "error"
    ]
    if result.returncode != 0 or errors:
        rendered = "\n".join(
            str(record["message"].get("rendered", ""))
            for record in errors
            if isinstance(record.get("message"), dict)
        ).strip()
        detail = rendered or result.stderr.strip() or f"cargo exit {result.returncode}"
        raise RuntimeError(f"{fixture.name} does not compile:\n{detail[-2000:]}")
    return records


def _validated_fixture_records(
    fixture: Path,
    key: str,
    lint: str,
    run_lint: str,
    should_fire: bool,
    manifest: Path,
    target: Path,
) -> list[dict[str, object]]:
    records = run_fixture(fixture, run_lint, manifest, target)
    matching = [record for record in records if diagnostic_code(record) == run_lint]
    if should_fire and not matching:
        raise RuntimeError(f"{key}: {fixture.name} did not emit {run_lint}")
    if not should_fire and matching:
        raise RuntimeError(f"{key}: {fixture.name} unexpectedly emitted {run_lint}")
    if not should_fire:
        return []
    for record in matching:
        if run_lint != lint:
            record["message"]["code"]["code"] = lint
        rewrite_span_paths(record, fixture.name)
    return matching


def _fixture_pairs(item: dict[str, object]) -> tuple[tuple[str, bool], ...]:
    bad_name = str(item["bad"])
    good_name = str(item.get("good") or bad_name.replace("_bad", "_good"))
    return ((bad_name, True), (good_name, False))


def generate_report(project_dir: Path, output_path: Path) -> int:
    """Validate all pairs and write bad-fixture target diagnostics as JSONL."""
    items = expectations(project_dir)
    validate_mapping(project_dir)
    combined: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="rust-clippy-oracle-") as directory:
        temp = Path(directory)
        manifest = temp / "Cargo.toml"
        target = temp / "target"
        for item in items:
            key = item["key"]
            assert isinstance(key, str)
            if key in NATIVE_RULES:
                continue
            lint = CLIPPY_LINTS[key]
            run_lint = RUN_LINTS.get(key, lint)
            for fixture_name, should_fire in _fixture_pairs(item):
                fixture = project_dir / "src" / fixture_name
                combined.extend(
                    _validated_fixture_records(
                        fixture,
                        key,
                        lint,
                        run_lint,
                        should_fire,
                        manifest,
                        target,
                    )
                )
    write_text_atomic(
        output_path, "".join(json.dumps(record) + "\n" for record in combined)
    )
    return len(combined)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project_dir", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    count = generate_report(args.project_dir.resolve(), args.output.resolve())
    print(f"wrote {count} Clippy diagnostic(s) to {args.output}")
