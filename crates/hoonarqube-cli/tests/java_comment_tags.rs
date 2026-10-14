use std::path::PathBuf;
use std::process::{Command, Output};

struct Fixture(PathBuf);

impl Fixture {
    fn new(label: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-java-comments-{label}-{}-{id}",
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
            .expect("run CLI")
    }

    fn write(&self, source: &[u8]) {
        std::fs::write(self.0.join("Control.java"), source).expect("write source");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn targets<'a>(report: &'a serde_json::Value, format: &str) -> Vec<&'a serde_json::Value> {
    let (issues, key) = if format == "json" {
        assert_eq!(report["project"]["complete"], true);
        (
            report["files"][0]["issues"]
                .as_array()
                .expect("native issues"),
            "rule_key",
        )
    } else {
        (
            report["issues"].as_array().expect("Generic issues"),
            "ruleId",
        )
    };
    issues
        .iter()
        .filter(|issue| matches!(issue[key].as_str(), Some("java:S1134" | "java:S1135")))
        .collect()
}

#[test]
fn java_comment_tags_cli_matches_reference_codepoints_utf16_and_duplicate_trivia() {
    let fixture = Fixture::new("identity");
    for (source, expected, native_end, generic_end) in [
        (
            include_str!("../../hoonarqube-java/tests/fixtures/comment_tags/AstralLetters.java"),
            2,
            17,
            21,
        ),
        (
            include_str!("../../hoonarqube-java/tests/fixtures/comment_tags/MultipleTrivia.java"),
            3,
            30,
            30,
        ),
    ] {
        fixture.write(source.as_bytes());
        for format in ["json", "sonar"] {
            let output = fixture.run(&[
                "analyze",
                "--profile",
                "sonar-parity",
                "--format",
                format,
                "--",
                "Control.java",
            ]);
            assert!(output.status.success(), "{output:?}");
            let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("report");
            let findings = targets(&report, format);
            assert_eq!(findings.len(), expected);
            for issue in findings {
                let key = if format == "json" {
                    "rule_key"
                } else {
                    "ruleId"
                };
                let message = if issue[key] == "java:S1134" {
                    "Take the required action to fix the issue indicated by this comment."
                } else {
                    "Complete the task associated to this TODO comment."
                };
                if format == "json" {
                    assert_eq!(issue["message"], message);
                    assert_eq!(
                        issue["range"],
                        serde_json::json!({"start":{"line":1,"column":0},"end":{"line":1,"column":native_end}})
                    );
                    assert!(issue.get("fix").is_none());
                    assert!(issue.get("flows").is_none());
                    assert!(issue.get("alternatives").is_none());
                } else {
                    assert_eq!(issue["primaryLocation"]["message"], message);
                    assert_eq!(
                        issue["primaryLocation"]["textRange"],
                        serde_json::json!({"startLine":1,"startColumn":0,"endLine":1,"endColumn":generic_end})
                    );
                    assert!(issue.get("secondaryLocations").is_none());
                }
            }
        }
        assert_eq!(
            std::fs::read(fixture.0.join("Control.java")).expect("readback"),
            source.as_bytes()
        );
    }
}

#[test]
fn java_comment_tags_cli_keeps_literals_and_first_embedded_occurrence_clean() {
    let fixture = Fixture::new("clean");
    for source in [
        include_str!("../../hoonarqube-java/tests/fixtures/comment_tags/Literals.java"),
        include_str!("../../hoonarqube-java/tests/fixtures/comment_tags/FirstEmbedded.java"),
    ] {
        fixture.write(source.as_bytes());
        for format in ["json", "sonar"] {
            let output = fixture.run(&[
                "analyze",
                "--profile",
                "sonar-parity",
                "--format",
                format,
                "--",
                "Control.java",
            ]);
            assert!(output.status.success(), "{output:?}");
            let report = serde_json::from_slice(&output.stdout).expect("report");
            assert!(targets(&report, format).is_empty());
        }
    }
}

#[test]
fn java_comment_tags_cli_preserves_incomplete_analysis_and_source_bytes() {
    let fixture = Fixture::new("incomplete");
    for source in [
        b"class Broken { void broken( // TODO FIXME\n".as_slice(),
        b"\xff// TODO FIXME\n".as_slice(),
    ] {
        fixture.write(source);
        let output = fixture.run(&[
            "analyze",
            "--profile",
            "sonar-parity",
            "--format",
            "json",
            "--",
            "Control.java",
        ]);
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        let report: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("incomplete report");
        assert_eq!(report["project"]["complete"], false);
        assert_eq!(
            std::fs::read(fixture.0.join("Control.java")).expect("readback"),
            source
        );
    }
}

#[test]
fn java_comment_tags_cli_preserves_trivia_multiplicity_in_every_active_profile() {
    let fixture = Fixture::new("profiles");
    let source =
        include_str!("../../hoonarqube-java/tests/fixtures/comment_tags/MultipleTrivia.java");
    fixture.write(source.as_bytes());
    for profile in [
        None,
        Some("sonar-parity"),
        Some("recommended"),
        Some("extended"),
        Some("strict"),
    ] {
        for format in ["json", "sonar"] {
            let mut args = vec!["analyze", "--format", format];
            if let Some(profile) = profile {
                args.extend(["--profile", profile]);
            }
            args.extend(["--", "Control.java"]);
            let output = fixture.run(&args);
            assert!(output.status.success(), "{profile:?}: {output:?}");
            let report = serde_json::from_slice(&output.stdout).expect("report");
            assert_eq!(targets(&report, format).len(), 3, "{profile:?}/{format}");
        }
    }
    assert_eq!(
        std::fs::read(fixture.0.join("Control.java")).unwrap(),
        source.as_bytes()
    );
}
