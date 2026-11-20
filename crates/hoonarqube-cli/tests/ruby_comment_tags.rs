use std::path::PathBuf;
use std::process::{Command, Output};

struct Fixture(PathBuf);

impl Fixture {
    fn new(label: &str) -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-ruby-comments-{label}-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("fixture directory");
        Self(path)
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args(args)
            .output()
            .expect("run hoonarqube")
    }

    fn write(&self, source: &[u8]) {
        std::fs::write(self.0.join("control.rb"), source).expect("fixture source");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn target_issues<'a>(report: &'a serde_json::Value, format: &str) -> Vec<&'a serde_json::Value> {
    let (issues, key) = if format == "json" {
        assert_eq!(report["project"]["complete"], true);
        (
            report["files"][0]["issues"]
                .as_array()
                .expect("native issues"),
            "rule_key",
        )
    } else {
        (report["issues"].as_array().expect("Sonar issues"), "ruleId")
    };
    issues
        .iter()
        .filter(|issue| matches!(issue[key].as_str(), Some("ruby:S1134" | "ruby:S1135")))
        .collect()
}

fn assert_identity(output: &Output, format: &str) {
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("analysis JSON");
    let findings = target_issues(&report, format);
    assert_eq!(findings.len(), 2);
    if format == "json" {
        assert_eq!(findings[0]["rule_key"], "ruby:S1135");
        assert_eq!(findings[1]["rule_key"], "ruby:S1134");
        assert_eq!(
            findings[0]["range"],
            serde_json::json!({"start":{"line":1,"column":3},"end":{"line":1,"column":7}})
        );
        assert_eq!(
            findings[1]["range"],
            serde_json::json!({"start":{"line":1,"column":9},"end":{"line":1,"column":14}})
        );
        for issue in findings {
            assert!(issue.get("fix").is_none());
            assert!(issue.get("alternatives").is_none());
            assert!(issue.get("flows").is_none());
        }
    } else {
        assert_eq!(findings[0]["primaryLocation"]["filePath"], "control.rb");
        assert_eq!(
            findings[0]["primaryLocation"]["textRange"],
            serde_json::json!({"startLine":1,"startColumn":4,"endLine":1,"endColumn":8})
        );
        assert_eq!(
            findings[1]["primaryLocation"]["textRange"],
            serde_json::json!({"startLine":1,"startColumn":11,"endLine":1,"endColumn":16})
        );
        assert_eq!(
            findings[0]["primaryLocation"]["message"],
            "Complete the task associated to this TODO comment."
        );
        assert_eq!(
            findings[1]["primaryLocation"]["message"],
            "Take the required action to fix the issue indicated by this \"FIXME\" comment."
        );
    }
}

#[test]
fn ruby_comment_tags_cli_has_exact_code_point_and_utf16_identities_without_actions() {
    let fixture = Fixture::new("identity");
    let source = "# 🦉TODO 🦉FIXME TODO FIXME\r\nvalue = 1\r\n".as_bytes();
    fixture.write(source);
    for format in ["json", "sonar"] {
        let output = fixture.run(&[
            "analyze",
            "--profile",
            "sonar-parity",
            "--format",
            format,
            "--",
            "control.rb",
        ]);
        assert_identity(&output, format);
    }
    assert_eq!(
        std::fs::read(fixture.0.join("control.rb")).expect("readback"),
        source
    );
}

#[test]
fn ruby_comment_tags_cli_keeps_literal_and_boundary_controls_clean() {
    let fixture = Fixture::new("clean");
    let source = b"# xTODO TODO1 xFIXME FIXME2\na = '# TODO FIXME'\nvalue = <<~TEXT\n# TODO FIXME\nTEXT\n__END__\n# TODO FIXME\n";
    fixture.write(source);
    for format in ["json", "sonar"] {
        let output = fixture.run(&[
            "analyze",
            "--profile",
            "sonar-parity",
            "--format",
            format,
            "--",
            "control.rb",
        ]);
        assert!(output.status.success(), "{output:?}");
        let report: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("analysis JSON");
        assert!(target_issues(&report, format).is_empty());
    }
    assert_eq!(
        std::fs::read(fixture.0.join("control.rb")).expect("readback"),
        source
    );
}

#[test]
fn ruby_comment_tags_cli_preserves_malformed_and_invalid_utf8_incomplete_analysis() {
    let fixture = Fixture::new("incomplete");
    for source in [
        b"def broken(\n# TODO FIXME\n".as_slice(),
        b"\xff# TODO FIXME\n".as_slice(),
    ] {
        fixture.write(source);
        let output = fixture.run(&[
            "analyze",
            "--profile",
            "sonar-parity",
            "--format",
            "json",
            "--",
            "control.rb",
        ]);
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        let report: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("incomplete JSON");
        assert_eq!(report["project"]["complete"], false);
        assert_eq!(
            std::fs::read(fixture.0.join("control.rb")).expect("readback"),
            source
        );
    }
}

#[test]
fn ruby_comment_tags_cli_refuses_unavailable_actions_without_writing() {
    let fixture = Fixture::new("refusal");
    let source = b"# TODO FIXME\nvalue = 1\n";
    fixture.write(source);
    for selection in ["ruby:S1134=remove-comment", "ruby:S1135=remove-comment"] {
        for mode in ["--diff", "--apply"] {
            let output = fixture.run(&[
                "fix",
                "control.rb",
                mode,
                "--json",
                "--suggestion",
                selection,
            ]);
            assert_eq!(output.status.code(), Some(1), "{output:?}");
            assert!(String::from_utf8_lossy(&output.stderr).contains("is unavailable"));
            let report: serde_json::Value =
                serde_json::from_slice(&output.stdout).expect("refused fix JSON");
            assert_eq!(report["files"], serde_json::json!([]));
            assert_eq!(
                std::fs::read(fixture.0.join("control.rb")).expect("readback"),
                source
            );
        }
    }
}
