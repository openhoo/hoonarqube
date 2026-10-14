use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::{Command, Output};

struct Fixture(PathBuf);

impl Fixture {
    fn new(label: &str) -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-jsts-s1067-{label}-{}-{id}",
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

fn check_language(extension: &str, language: &str) {
    let fixture = Fixture::new(extension);
    std::fs::create_dir(fixture.0.join("src")).expect("source directory");
    let cases = [
        (
            "four",
            "while (a && !b && c || d || e) {\n  g();\n}\n",
            Some(Expected {
                message: "Reduce the number of conditional operators (4) used in the expression (maximum allowed 3).",
                start: 7,
                end: 29,
            }),
        ),
        (
            "eleven",
            "const value = a && b && c && d && e && f && g && h && i && j && k && l;\n",
            Some(Expected {
                message: "Reduce the number of conditional operators (11) used in the expression (maximum allowed 3).",
                start: 14,
                end: 70,
            }),
        ),
        ("clean", "if (a && b && c && d) {\n  g();\n}\n", None),
    ];
    for (label, source, _) in &cases {
        std::fs::write(fixture.0.join(format!("src/{label}.{extension}")), source)
            .expect("fixture source");
    }
    let native = fixture.analyze("src", "json");
    let generic = fixture.analyze("src", "sonar");
    assert_eq!(native["project"]["complete"], true);
    assert_eq!(native["files"].as_array().expect("native files").len(), 3);
    let inventory = native["project"]["files"].as_array().expect("inventory");
    assert_eq!(inventory.len(), 3);
    assert!(inventory.iter().all(|entry| entry["status"] == "complete"));
    for (label, source, expected) in cases {
        let file = format!("src/{label}.{extension}");
        assert_reports(
            &native,
            &generic,
            &file,
            &format!("{language}:S1067"),
            expected,
        );
        assert_eq!(
            std::fs::read(fixture.0.join(file)).expect("source readback"),
            source.as_bytes()
        );
    }
}

#[test]
fn s1067_cli_javascript_messages_ranges_and_clean_control() {
    check_language("js", "javascript");
}

#[test]
fn s1067_cli_typescript_messages_ranges_and_clean_control() {
    check_language("ts", "typescript");
}

#[test]
fn s1067_cli_invalid_source_remains_incomplete_without_writing() {
    let fixture = Fixture::new("invalid");
    let source = b"\xffwhile (a && b && c && d && e) {}\n";
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
fn s1067_cli_unavailable_fix_refuses_and_preserves_all_diagnostics() {
    let fixture = Fixture::new("refusal");
    let source = b"while (a && !b && c || d || e) {\n  g();\n}\n";
    for (extension, language) in [("js", "javascript"), ("ts", "typescript")] {
        let file = format!("case.{extension}");
        let path = fixture.0.join(&file);
        std::fs::write(&path, source).expect("fixture source");
        let before = fixture.analyze(&file, "json");
        let action = format!("{language}:S1067=s1067-reduce-conditional-operators");
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
