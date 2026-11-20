use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::{Command, Output};

const CONTROLS: &str = include_str!("../../hoonarqube-rust/fixtures/s7411_ranges.rs");
const KEY: &str = "rust:S7411";

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("hoonarqube-s7411-{}-{id}", std::process::id()));
        std::fs::create_dir(&path).expect("fixture directory");
        Self(path)
    }

    fn write(&self, source: &[u8]) {
        std::fs::write(self.0.join("ranges.rs"), source).expect("source");
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args(args)
            .output()
            .expect("actual CLI")
    }

    fn analyze(&self, profile: &str, format: &str, exit: i32) -> Value {
        let mut args = vec!["analyze", "--format", format];
        if profile != "default" {
            args.extend(["--profile", profile]);
        }
        args.extend(["--", "ranges.rs"]);
        let output = self.run(&args);
        assert_eq!(output.status.code(), Some(exit), "{output:?}");
        serde_json::from_slice(&output.stdout).expect("actual JSON document")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn selected<'a>(document: &'a Value, format: &str) -> Vec<&'a Value> {
    if format == "json" {
        document["files"]
            .as_array()
            .expect("native files")
            .iter()
            .flat_map(|file| file["issues"].as_array().expect("native issues"))
            .filter(|issue| issue["rule_key"] == KEY)
            .collect()
    } else {
        document["issues"]
            .as_array()
            .expect("generic issues")
            .iter()
            .filter(|issue| issue["ruleId"] == KEY)
            .collect()
    }
}

fn assert_ranges(document: &Value, format: &str) {
    let expected = [
        (3, 4, 4, 19),
        (14, 4, 16, 19),
        (32, 4, 33, 5),
        (44, 4, 46, 5),
        (51, 4, 52, 19),
        (67, 11, 73, 5),
        (87, 4, 88, 19),
    ];
    let issues = selected(document, format);
    assert_eq!(issues.len(), expected.len());
    for (issue, (sl, sc, el, ec)) in issues.into_iter().zip(expected) {
        let (range, message) = if format == "json" {
            assert!(issue.get("fix").is_none());
            assert!(issue.get("alternatives").is_none());
            assert!(issue.get("flows").is_none());
            (issue["range"].clone(), &issue["message"])
        } else {
            assert!(issue.get("secondaryLocations").is_none());
            assert_eq!(issue["primaryLocation"]["filePath"], "ranges.rs");
            (
                issue["primaryLocation"]["textRange"].clone(),
                &issue["primaryLocation"]["message"],
            )
        };
        assert_eq!(
            message,
            "Refactor the code to avoid duplicating logic in multiple branches."
        );
        let expected_range = if format == "json" {
            json!({"start":{"line":sl,"column":sc}, "end":{"line":el,"column":ec}})
        } else {
            json!({"startLine":sl,"startColumn":sc,"endLine":el,"endColumn":ec})
        };
        assert_eq!(range, expected_range);
    }
}

#[test]
fn rust_s7411_cli_two_block_ranges_match_reference_and_keep_chain_residual() {
    let fixture = Fixture::new();
    for source in [CONTROLS.to_string(), CONTROLS.replace('\n', "\r\n")] {
        fixture.write(source.as_bytes());
        for profile in [
            "default",
            "sonar-parity",
            "recommended",
            "extended",
            "strict",
        ] {
            for format in ["json", "sonar"] {
                let document = fixture.analyze(profile, format, 0);
                assert_ranges(&document, format);
                if format == "json" {
                    assert_eq!(document["project"]["complete"], true);
                }
            }
        }
        assert_eq!(
            std::fs::read(fixture.0.join("ranges.rs")).expect("readback"),
            source.as_bytes()
        );
    }
}

#[test]
fn rust_s7411_cli_unicode_native_and_generic_columns_remain_distinct() {
    let fixture = Fixture::new();
    let source = "fn f(flag: bool) {\n    if flag {\n        t(\"🦉\");\n        a();\n    } else {\n        t(\"🦉\");\n        b();\n    }\n}\n";
    fixture.write(source.as_bytes());
    let native = fixture.analyze("sonar-parity", "json", 0);
    let generic = fixture.analyze("sonar-parity", "sonar", 0);
    let native = selected(&native, "json");
    let generic = selected(&generic, "sonar");
    assert_eq!(native.len(), 1);
    assert_eq!(generic.len(), 1);
    assert_eq!(
        native[0]["range"],
        json!({"start":{"line":2,"column":4},"end":{"line":3,"column":15}})
    );
    assert_eq!(
        generic[0]["primaryLocation"]["textRange"],
        json!({"startLine":2,"startColumn":4,"endLine":3,"endColumn":16})
    );
}

#[test]
fn rust_s7411_cli_malformed_and_invalid_utf8_remain_incomplete() {
    let fixture = Fixture::new();
    for source in [b"fn broken(".as_slice(), b"\xff\n".as_slice()] {
        fixture.write(source);
        for format in ["json", "sonar"] {
            let document = fixture.analyze("sonar-parity", format, 2);
            assert!(selected(&document, format).is_empty());
            assert_eq!(document["parity"]["completeness"], "incomplete");
            if format == "json" {
                assert_eq!(document["project"]["complete"], false);
            }
        }
        assert_eq!(
            std::fs::read(fixture.0.join("ranges.rs")).expect("readback"),
            source
        );
    }
}

#[test]
fn rust_s7411_cli_unavailable_fix_preserves_source_and_report() {
    let fixture = Fixture::new();
    fixture.write(CONTROLS.as_bytes());
    let before = fixture.analyze("strict", "json", 0);
    for mode in ["--diff", "--apply"] {
        let output = fixture.run(&[
            "fix",
            "--profile",
            "strict",
            "--rule",
            KEY,
            "--suggestion",
            "rust:S7411=extract-shared-code",
            mode,
            "--json",
            "ranges.rs",
        ]);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let report: Value = serde_json::from_slice(&output.stdout).expect("fix report");
        assert_eq!(report["applied"], 0);
        assert_eq!(report["mechanical"], 0);
        assert_eq!(report["files"], json!([]));
        assert_eq!(fixture.analyze("strict", "json", 0), before);
        assert_eq!(
            std::fs::read(fixture.0.join("ranges.rs")).expect("readback"),
            CONTROLS.as_bytes()
        );
    }
}
