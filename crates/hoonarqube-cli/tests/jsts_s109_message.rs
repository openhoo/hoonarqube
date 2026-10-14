use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::{Command, Output};

struct Fixture(PathBuf);

impl Fixture {
    fn new(label: &str) -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-jsts-s109-{label}-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("fixture directory");
        Self(path)
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args(args)
            .output()
            .expect("run hoonarqube")
    }

    fn analyze(&self, path: &str, format: &str) -> Value {
        let output = self.run(&[
            "analyze",
            "--profile",
            "sonar-parity",
            "--format",
            format,
            "--",
            path,
        ]);
        assert!(output.status.success(), "{output:?}");
        serde_json::from_slice(&output.stdout).expect("analysis report")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Expected {
    message: &'static str,
    start: u32,
    end: u32,
}

fn assert_reports(
    native: &Value,
    generic: &Value,
    file: &str,
    key: &str,
    expected: Option<Expected>,
) {
    let native_file = native["files"]
        .as_array()
        .expect("native files")
        .iter()
        .find(|entry| entry["path"] == file)
        .expect("analyzed file");
    let native_issues: Vec<_> = native_file["issues"]
        .as_array()
        .expect("native issues")
        .iter()
        .filter(|issue| issue["rule_key"] == key)
        .collect();
    let generic_issues: Vec<_> = generic["issues"]
        .as_array()
        .expect("generic issues")
        .iter()
        .filter(|issue| issue["ruleId"] == key && issue["primaryLocation"]["filePath"] == file)
        .collect();
    assert_eq!(native_issues.len(), usize::from(expected.is_some()));
    assert_eq!(generic_issues.len(), native_issues.len());
    if let Some(expected) = expected {
        assert_eq!(
            native_issues[0],
            &json!({
                "rule_key": key,
                "message": expected.message,
                "range": {
                    "start": {"line": 1, "column": expected.start},
                    "end": {"line": 1, "column": expected.end},
                },
            })
        );
        assert_eq!(
            generic_issues[0],
            &json!({
                "ruleId": key,
                "primaryLocation": {
                    "filePath": file,
                    "message": expected.message,
                    "textRange": {
                        "startLine": 1, "startColumn": expected.start,
                        "endLine": 1, "endColumn": expected.end,
                    },
                },
            })
        );
    }
}

type Case = (&'static str, &'static str, Option<Expected>);

fn positive_case(
    label: &'static str,
    source: &'static str,
    message: &'static str,
    start: u32,
    end: u32,
) -> Case {
    (
        label,
        source,
        Some(Expected {
            message,
            start,
            end,
        }),
    )
}

fn check_language(extension: &str, language: &str) {
    let fixture = Fixture::new(extension);
    std::fs::create_dir(fixture.0.join("src")).expect("source directory");
    // Message authority: installed SonarJS 13.8 core no-magic-numbers emitter.
    // Numeric-only native primary ranges are deliberately retained.
    let cases = [
        positive_case("decimal", "g(45);\n", "No magic number: 45.", 2, 4),
        positive_case("hex", "g(0x3e);\n", "No magic number: 0x3e.", 2, 6),
        positive_case(
            "hex-case",
            "g(0x1F984);\n",
            "No magic number: 0x1F984.",
            2,
            9,
        ),
        positive_case("octal", "g(0o777);\n", "No magic number: 0o777.", 2, 7),
        positive_case(
            "exponent",
            "g(3.4028234663852886e38);\n",
            "No magic number: 3.4028234663852886e38.",
            2,
            23,
        ),
        positive_case(
            "decimal-zeros",
            "g(45.00);\n",
            "No magic number: 45.00.",
            2,
            7,
        ),
        positive_case("separator", "g(4_500);\n", "No magic number: 4_500.", 2, 7),
        positive_case("negative", "g(-3);\n", "No magic number: -3.", 3, 4),
        positive_case("plus", "g(+3);\n", "No magic number: +3.", 3, 4),
        positive_case("parenthesized", "g(-(3));\n", "No magic number: -3.", 4, 5),
        positive_case(
            "unary-ancestor",
            "g(-(g(3)));\n",
            "No magic number: 3.",
            6,
            7,
        ),
        ("clean", "const RETRIES = 3;\n", None),
        ("ignored-values", "g(0, 1, -1, 24, 60, 2, 16, 100);\n", None),
        ("bigint", "g(45n);\n", None),
    ];
    for (label, source, _) in &cases {
        std::fs::write(fixture.0.join(format!("src/{label}.{extension}")), source)
            .expect("fixture source");
    }
    let native = fixture.analyze("src", "json");
    let generic = fixture.analyze("src", "sonar");
    assert_eq!(native["project"]["complete"], true);
    assert_eq!(native["files"].as_array().expect("native files").len(), 14);
    let inventory = native["project"]["files"].as_array().expect("inventory");
    assert_eq!(inventory.len(), 14);
    assert!(inventory.iter().all(|entry| entry["status"] == "complete"));
    for (label, source, expected) in cases {
        let file = format!("src/{label}.{extension}");
        assert_reports(
            &native,
            &generic,
            &file,
            &format!("{language}:S109"),
            expected,
        );
        assert_eq!(
            std::fs::read(fixture.0.join(file)).expect("source readback"),
            source.as_bytes()
        );
    }
}

#[test]
fn s109_cli_javascript_messages_ranges_and_clean_control() {
    check_language("js", "javascript");
}

#[test]
fn s109_cli_typescript_messages_ranges_and_clean_control() {
    check_language("ts", "typescript");
}

#[test]
fn s109_cli_invalid_source_remains_incomplete_without_writing() {
    let fixture = Fixture::new("invalid");
    let source = b"\xffg(45);\n";
    for extension in ["js", "ts"] {
        let file = format!("invalid.{extension}");
        let path = fixture.0.join(&file);
        std::fs::write(&path, source).expect("invalid source");
        let output = fixture.run(&["analyze", "--format", "json", "--", &file]);
        assert_eq!(output.status.code(), Some(2));
        let report: Value = serde_json::from_slice(&output.stdout).expect("incomplete report");
        assert_eq!(report["project"]["complete"], false);
        assert_eq!(report["project"]["files"][0]["status"], "failed");
        assert_eq!(report["files"], json!([]));
        assert_eq!(std::fs::read(path).expect("source readback"), source);
    }
}

#[test]
fn s109_cli_unavailable_fix_refuses_and_preserves_all_diagnostics() {
    let fixture = Fixture::new("refusal");
    let source = b"g(45);\n";
    for (extension, language) in [("js", "javascript"), ("ts", "typescript")] {
        let file = format!("case.{extension}");
        let path = fixture.0.join(&file);
        std::fs::write(&path, source).expect("fixture source");
        let before = fixture.analyze(&file, "json");
        let action = format!("{language}:S109=s109-extract-named-constant");
        for mode in ["--diff", "--apply"] {
            let output = fixture.run(&["fix", &file, mode, "--json", "--suggestion", &action]);
            assert_eq!(output.status.code(), Some(1));
            assert!(String::from_utf8_lossy(&output.stderr).contains("is unavailable"));
            let report: Value = serde_json::from_slice(&output.stdout).expect("refused fix report");
            assert_eq!(report["files"], json!([]));
            assert_eq!(std::fs::read(&path).expect("source readback"), source);
            assert_eq!(fixture.analyze(&file, "json"), before);
        }
    }
}
