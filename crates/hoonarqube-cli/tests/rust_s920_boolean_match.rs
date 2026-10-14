use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::{Value, json};

const MESSAGE: &str = "Replace this `match` expression with an `if-else` expression.";
// Exact typed source observed by Clippy 1.96.0 and the real Sonar Rust analyzer.
const REFERENCE_CONTROLS: &str = concat!(
    "pub fn boolean(flag: bool) -> u8 {\n",
    "    match flag { true => 1, false => 2 }\n",
    "}\n",
    "pub fn one_arm(flag: bool) -> u8 {\n",
    "    match flag { _ => 1 }\n",
    "}\n",
    "pub fn binding(flag: bool) -> u8 {\n",
    "    match flag { true => 1, other => u8::from(other) }\n",
    "}\n",
    "pub fn three_arms(flag: bool, gate: bool) -> u8 {\n",
    "    match flag { true if gate => 1, false => 2, _ => 3 }\n",
    "}\n",
    "pub fn integer_negation(value: u8) -> u8 {\n",
    "    match !value { 0 => 1, _ => 2 }\n",
    "}\n",
    "pub fn equality(value: u8) -> u8 {\n",
    "    match value == 1 { true => 1, false => 2 }\n",
    "}\n",
    "pub fn boolean_negation(flag: bool) -> u8 {\n",
    "    match !flag { true => 1, false => 2 }\n",
    "}\n",
    "pub fn guarded_pair(flag: bool, gate: bool) -> u8 {\n",
    "    match flag { true if gate => 1, _ => 2 }\n",
    "}\n",
    "pub fn wildcard_pair(flag: bool, gate: bool) -> u8 {\n",
    "    match flag { _ if gate => 1, _ => 2 }\n",
    "}\n",
    "pub fn renamed(value: bool) -> u8 {\n",
    "    match value {\n",
    "        true => 1,\n",
    "        false => 2,\n",
    "    }\n",
    "}\n",
);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("hoonarqube-rust-s920-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&path).expect("fixture directory");
        Self(path)
    }

    fn analyze(&self, source: &[u8], profile: &str, format: &str) -> Output {
        let path = self.0.join("control.rs");
        std::fs::write(&path, source).expect("fixture source");
        let output = Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args([
                "analyze",
                "control.rs",
                "--profile",
                profile,
                "--format",
                format,
            ])
            .output()
            .expect("run hoonarqube");
        assert_eq!(std::fs::read(&path).expect("source readback"), source);
        output
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn selected(report: &Value, format: &str) -> Vec<Value> {
    let issues = if format == "json" {
        &report["files"][0]["issues"]
    } else {
        &report["issues"]
    };
    issues
        .as_array()
        .expect("issue array")
        .iter()
        .filter(|issue| {
            issue[if format == "json" {
                "rule_key"
            } else {
                "ruleId"
            }] == "rust:S920"
        })
        .cloned()
        .collect()
}

fn expected(format: &str, span: [u32; 4]) -> Value {
    let [start_line, start_column, end_line, end_column] = span;
    if format == "json" {
        json!({
            "rule_key": "rust:S920", "message": MESSAGE,
            "range": {
                "start": {"line": start_line, "column": start_column},
                "end": {"line": end_line, "column": end_column}
            }
        })
    } else {
        json!({
            "ruleId": "rust:S920",
            "primaryLocation": {
                "filePath": "control.rs", "message": MESSAGE,
                "textRange": {
                    "startLine": start_line, "startColumn": start_column,
                    "endLine": end_line, "endColumn": end_column
                }
            }
        })
    }
}

fn assert_issues(source: &str, spans: &[[u32; 4]]) {
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            let fixture = Fixture::new();
            let output = fixture.analyze(source.as_bytes(), profile, format);
            assert!(output.status.success(), "{profile}/{format}: {output:?}");
            let report: Value = serde_json::from_slice(&output.stdout).expect("report JSON");
            if format == "json" {
                assert_eq!(report["project"]["complete"], true);
                assert_eq!(report["project"]["files"][0]["status"], "complete");
            }
            let expected: Vec<_> = spans.iter().map(|span| expected(format, *span)).collect();
            assert_eq!(
                selected(&report, format),
                expected,
                "{profile}/{format}: {source}"
            );
        }
    }
}

#[test]
fn rust_s920_cli_matches_all_six_real_reference_identities() {
    assert_issues(
        REFERENCE_CONTROLS,
        &[
            [2, 4, 2, 40],
            [17, 4, 17, 46],
            [20, 4, 20, 41],
            [23, 4, 23, 44],
            [26, 4, 26, 41],
            [29, 4, 32, 5],
        ],
    );
}

#[test]
fn rust_s920_cli_rejects_arm_bindings_counts_and_integer_negation() {
    for source in [
        "fn f(flag: bool) { match flag { _ => () } }\n",
        "fn f(flag: bool) { match flag { true => (), other => drop(other) } }\n",
        "fn f(flag: bool, gate: bool) { match flag { true if gate => (), false => (), _ => () } }\n",
        "fn f(value: u8) { match !value { 0 => (), _ => () } }\n",
        "fn f(flag: bool) { match flag { bound @ true => drop(bound), _ => () } }\n",
    ] {
        assert_issues(source, &[]);
    }
}

#[test]
fn rust_s920_cli_preserves_distinct_whole_ranges_and_source_anchor_multiplicity() {
    let source = concat!(
        "fn choose(value: bool) {\n",
        "    match value {\n",
        "        true => (),\n",
        "        false => (),\n",
        "    };\n",
        "    match value {\n",
        "        false => (),\n",
        "        _ => (),\n",
        "    };\n",
        "}\n",
    );
    assert_issues(source, &[[2, 4, 5, 5], [6, 4, 9, 5]]);
    assert_issues(
        "fn f(値: bool) { let _ = \"🦉\"; match 値 { true => (), false => () }; }\r\n",
        &[[1, 29, 1, 63]],
    );
}

#[test]
fn rust_s920_cli_proves_local_booleans_and_keeps_guarded_wildcard_pairs() {
    for source in [
        "fn f(gate: bool) { let flag = true; match flag { _ if gate => (), _ => () }; }\n",
        "fn f(gate: bool) { let flag: bool = unknown(); match flag { _ if gate => (), _ => () }; }\n",
        "fn f(gate: bool, mut flag: bool) { match flag { _ if gate => (), _ => () }; }\n",
        "fn f(gate: bool) { let flag = gate; let next = flag; match next { _ if gate => (), _ => () }; }\n",
        "fn f(gate: bool) { match !gate { _ if gate => (), _ => () }; }\n",
        "fn f(gate: bool, x: u8) { match x < 2 { _ if gate => (), _ => () }; }\n",
        "fn f(gate: bool, x: bool) { match x && gate { _ if gate => (), _ => () }; }\n",
    ] {
        // These are supplementary source-only controls. Exact whole spans are
        // checked separately against the six independent reference identities.
        for format in ["json", "sonar"] {
            let fixture = Fixture::new();
            let output = fixture.analyze(source.as_bytes(), "sonar-parity", format);
            assert!(output.status.success(), "{output:?}");
            let report: Value = serde_json::from_slice(&output.stdout).expect("report JSON");
            assert_eq!(selected(&report, format).len(), 1, "{source}");
        }
    }
}

#[test]
fn rust_s920_cli_refuses_shadowed_ambiguous_and_nonlocal_boolean_facts() {
    for source in [
        "fn f(flag: bool, gate: bool) { let flag = 1u8; match flag { _ if gate => (), _ => () }; }\n",
        "fn f(flag: bool, gate: bool) { let flag = unknown(); match flag { _ if gate => (), _ => () }; }\n",
        "fn f(flag: bool, gate: bool) { let (flag,) = (1u8,); match flag { _ if gate => (), _ => () }; }\n",
        "fn f(flag: bool, gate: bool) { let closure = |flag: u8| match flag { _ if gate => (), _ => () }; drop(closure); }\n",
        "fn f(flag: bool, gate: bool) { for flag in [1u8] { match flag { _ if gate => (), _ => () }; } }\n",
        "fn f(flag: bool, gate: bool) { if let Some(flag) = Some(1u8) { match flag { _ if gate => (), _ => () }; } }\n",
        "fn f(flag: bool, gate: bool) { match Some(1u8) { Some(flag) => { match flag { _ if gate => (), _ => () }; }, _ => () }; }\n",
        "fn f(flag: bool, gate: bool) { let flag; match flag { _ if gate => (), _ => () }; }\n",
        "const FLAG: bool = true; fn f(gate: bool) { match FLAG { _ if gate => (), _ => () }; }\n",
        "fn other(flag: bool) {} fn f(gate: bool) { match flag { _ if gate => (), _ => () }; }\n",
        "fn f(gate: bool) { match !unknown() { _ if gate => (), _ => () }; }\n",
        "fn f(value: u8, gate: bool) { match !value { _ if gate => (), _ => () }; }\n",
        "fn f(gate: bool) { let mut flag = true; if gate { flag = unknown(); } match flag { _ if gate => (), _ => () }; }\n",
    ] {
        assert_issues(source, &[]);
    }
}

#[test]
fn rust_s920_cli_malformed_and_invalid_utf8_remain_incomplete() {
    for source in [
        b"fn broken(flag: bool) { match flag { true => ()".as_slice(),
        b"\xff\n".as_slice(),
    ] {
        for format in ["json", "sonar"] {
            let fixture = Fixture::new();
            let output = fixture.analyze(source, "sonar-parity", format);
            assert_eq!(output.status.code(), Some(2), "{format}: {output:?}");
            let report: Value = serde_json::from_slice(&output.stdout).expect("report JSON");
            assert!(selected(&report, format).is_empty());
            if format == "json" {
                assert_eq!(report["project"]["complete"], false);
                assert_eq!(report["project"]["files"][0]["status"], "failed");
            }
        }
    }
}
