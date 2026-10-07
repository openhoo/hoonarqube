use serde_json::Value;
use std::process::{Command, Output};

struct Fixture(std::path::PathBuf);

impl Fixture {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-sonar-line-endings-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("create fixture directory");
        Self(path)
    }

    fn analyze(&self, name: &str, format: &str) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hoonarqube"));
        command
            .current_dir(&self.0)
            .args(["analyze", "--format", format]);
        if format == "sarif" {
            command.args(["--profile", "github-code-quality"]);
        }
        command
            .args(["--", name])
            .output()
            .expect("run hoonarqube CLI")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn document(output: &Output, label: &str, format: &str) -> Value {
    assert!(
        output.status.success(),
        "{label} {format}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("complete report JSON")
}

#[test]
fn sonar_cli_preserves_generic_trailing_lone_cr_at_end_of_file() {
    let fixture = Fixture::new();
    for (label, source, expected_eof) in [
        ("cr", "class A {\r  int x = 1;\r}\r", Some((24, 25))),
        ("lf", "class A {\n  int x = 1;\n}\n", None),
        ("crlf", "class A {\r\n  int x = 1;\r\n}\r\n", None),
        ("unicode-cr", "class A { /*😀*/ }\r", Some((18, 19))),
    ] {
        let name = format!("{label}.cs");
        let path = fixture.0.join(&name);
        std::fs::write(&path, source).expect("write C# fixture");
        let native = document(&fixture.analyze(&name, "json"), label, "json");
        let native_issues = native["files"][0]["issues"]
            .as_array()
            .expect("native issues");
        assert!(!native_issues.is_empty(), "{label} native findings");
        assert_eq!(
            native_issues
                .iter()
                .any(|issue| issue["rule_key"] == "csharpsquid:S113"),
            expected_eof.is_some(),
            "{label} native EOF"
        );
        let sonar = document(&fixture.analyze(&name, "sonar"), label, "sonar");
        let issues = sonar["issues"].as_array().expect("Sonar issues");
        assert_eq!(
            issues.len(),
            native_issues.len(),
            "{label} retains every finding"
        );
        if let Some((start, end)) = expected_eof {
            let eof = issues
                .iter()
                .find(|issue| issue["ruleId"] == "csharpsquid:S113")
                .expect("Sonar EOF finding");
            let range = &eof["primaryLocation"]["textRange"];
            assert_eq!(range["startLine"], 1, "{label} start line");
            assert_eq!(range["endLine"], 1, "{label} end line");
            assert_eq!(range["startColumn"], start, "{label} start column");
            assert_eq!(range["endColumn"], end, "{label} end column");
        }
        for format in ["text", "sarif", "gitlab-codequality"] {
            let output = fixture.analyze(&name, format);
            assert!(
                output.status.success(),
                "{label} {format}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(!output.stdout.is_empty(), "{label} {format} report");
        }
        assert_eq!(
            std::fs::read(path).expect("read fixture"),
            source.as_bytes()
        );
    }
}

#[test]
fn sonar_cli_retains_ecmascript_line_terminator_and_utf16_coordinates() {
    let fixture = Fixture::new();
    for (label, separator) in [
        ("lf", "\n"),
        ("crlf", "\r\n"),
        ("cr", "\r"),
        ("ls", "\u{2028}"),
        ("ps", "\u{2029}"),
    ] {
        let source = format!("let value = 1;{separator}/*😀*/ debugger;{separator}");
        let name = format!("{label}.js");
        std::fs::write(fixture.0.join(&name), &source).expect("write JavaScript fixture");
        let sonar = document(&fixture.analyze(&name, "sonar"), label, "sonar");
        let finding = sonar["issues"]
            .as_array()
            .expect("Sonar issues")
            .iter()
            .find(|issue| issue["ruleId"] == "javascript:S1525")
            .expect("debugger finding");
        let range = &finding["primaryLocation"]["textRange"];
        assert_eq!(range["startLine"], 2, "{label} start line");
        assert_eq!(range["endLine"], 2, "{label} end line");
        assert_eq!(range["startColumn"], 7, "{label} UTF-16 start");
        assert_eq!(range["endColumn"], 16, "{label} UTF-16 end");
        assert_eq!(
            std::fs::read(fixture.0.join(name)).expect("read fixture"),
            source.as_bytes()
        );
    }
}
