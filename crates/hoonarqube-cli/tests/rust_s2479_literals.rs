use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::{Value, json};

const MESSAGE: &str = "Remove this invisible character from this literal.";

struct Fixture(PathBuf);

impl Fixture {
    fn new(label: &str) -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-rust-s2479-{label}-{}-{id}",
            std::process::id()
        ));
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
            }] == "rust:S2479"
        })
        .cloned()
        .collect()
}

#[test]
fn rust_s2479_json_and_generic_match_real_reference_literal_identities() {
    // These five identities were observed with Clippy 1.96.0 and the real
    // Sonar Rust analyzer. Columns are the zero-based export coordinates.
    let controls = [
        (
            "pub fn character() { let _value = '\u{200b}'; }\n",
            1,
            34,
            37,
        ),
        (
            "pub fn formatted()\n{\n    let _value\n        = \"a\u{200b}b\";\n}\n",
            4,
            10,
            15,
        ),
        (
            "pub fn ordinary() { let _value = \"a\u{200b}b\u{2060}c\"; }\n",
            1,
            33,
            40,
        ),
        (
            "pub fn raw() { let _value = r#\"a\u{200b}b\"#; }\n",
            1,
            28,
            36,
        ),
        ("pub fn soft() { let _value = \"a\u{ad}b\"; }\n", 1, 29, 34),
        // A frozen source anchor previously added a duplicate identity.
        (
            "fn hidden() { let value = \"a\u{200b}b\"; drop(value); }\n",
            1,
            25,
            30,
        ),
    ];
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            for (source, line, start, end) in controls {
                let fixture = Fixture::new("identity");
                let output = fixture.analyze(source.as_bytes(), profile, format);
                assert!(output.status.success(), "{profile}/{format}: {output:?}");
                let report: Value = serde_json::from_slice(&output.stdout).expect("report JSON");
                let expected = if format == "json" {
                    assert_eq!(report["project"]["complete"], true);
                    assert_eq!(report["project"]["files"][0]["status"], "complete");
                    json!({
                        "rule_key": "rust:S2479", "message": MESSAGE,
                        "range": {
                            "start": {"line": line, "column": start},
                            "end": {"line": line, "column": end}
                        }
                    })
                } else {
                    json!({
                        "ruleId": "rust:S2479",
                        "primaryLocation": {
                            "filePath": "control.rs", "message": MESSAGE,
                            "textRange": {
                                "startLine": line, "endLine": line,
                                "startColumn": start, "endColumn": end
                            }
                        }
                    })
                };
                assert_eq!(selected(&report, format), vec![expected]);
            }
        }
    }
}

#[test]
fn rust_s2479_clean_comments_joiners_c_strings_and_escapes_stay_clean() {
    let source = concat!(
        "// Comment \u{200b}\u{2060}\u{ad}\n/* Block \u{200b} */\n",
        "pub fn clean() { let _joiners = \"\u{200c}\u{200d}\u{feff}\"; ",
        "let _escaped = \"a\\u{200b}b\"; let _c = c\"a\u{200b}b\"; }\n"
    );
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            let fixture = Fixture::new("clean");
            let output = fixture.analyze(source.as_bytes(), profile, format);
            assert!(output.status.success(), "{profile}/{format}: {output:?}");
            let report: Value = serde_json::from_slice(&output.stdout).expect("report JSON");
            if format == "json" {
                assert_eq!(report["project"]["complete"], true);
            }
            assert!(selected(&report, format).is_empty());
        }
    }
}

#[test]
fn rust_s2479_malformed_and_invalid_utf8_sources_remain_incomplete() {
    let malformed = "fn broken() { let _value = \"a\u{200b}b; }\n";
    for source in [malformed.as_bytes(), b"\xff\n".as_slice()] {
        for format in ["json", "sonar"] {
            let fixture = Fixture::new("incomplete");
            let output = fixture.analyze(source, "sonar-parity", format);
            assert_eq!(output.status.code(), Some(2), "{format}: {output:?}");
            let report: Value = serde_json::from_slice(&output.stdout).expect("report JSON");
            if format == "json" {
                assert_eq!(report["project"]["complete"], false);
                assert_eq!(report["project"]["files"][0]["status"], "failed");
            }
        }
    }
}
