use std::path::PathBuf;
use std::process::{Command, Output};

struct Fixture(PathBuf);

impl Fixture {
    fn new(label: &str) -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-jsts-s1451-{label}-{}-{id}",
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
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn assert_header_report(output: &Output, format: &str, file: &str, key: &str, expected: usize) {
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("analysis JSON");
    let findings: Vec<_> = if format == "json" {
        assert_eq!(report["project"]["complete"], true);
        report["files"]
            .as_array()
            .expect("files")
            .iter()
            .flat_map(|file| file["issues"].as_array().expect("issues"))
            .filter(|issue| issue["rule_key"] == key)
            .collect()
    } else {
        report["issues"]
            .as_array()
            .expect("generic issues")
            .iter()
            .filter(|issue| issue["ruleId"] == key)
            .collect()
    };
    assert_eq!(findings.len(), expected);
    if let Some(issue) = findings.first() {
        if format == "json" {
            assert_eq!(
                issue["range"],
                serde_json::json!({
                    "start": {"line": 0, "column": 0},
                    "end": {"line": 0, "column": 0},
                })
            );
            assert_eq!(issue["message"], "Add or update the header of this file.");
            assert!(issue.get("fix").is_none());
            assert!(issue.get("alternatives").is_none());
            assert!(issue.get("flows").is_none());
        } else {
            let primary = &issue["primaryLocation"];
            assert_eq!(primary["message"], "Add or update the header of this file.");
            assert_eq!(primary["filePath"], file);
            assert!(primary.get("textRange").is_none());
        }
    }
}

#[test]
fn s1451_cli_json_and_generic_report_file_level_identity_and_clean_controls() {
    let fixture = Fixture::new("identity");
    for (extension, language) in [("js", "javascript"), ("ts", "typescript")] {
        let file = format!("case.{extension}");
        let path = fixture.0.join(&file);
        let key = format!("{language}:S1451");
        for (source, expected) in [("const value = 1;\n", 1), ("\nconst value = 1;\n", 0)] {
            std::fs::write(&path, source).expect("fixture source");
            for format in ["json", "sonar"] {
                let output = fixture.run(&[
                    "analyze",
                    &file,
                    "--profile",
                    "sonar-parity",
                    "--format",
                    format,
                ]);
                assert_header_report(&output, format, &file, &key, expected);
                assert_eq!(
                    std::fs::read(&path).expect("source readback"),
                    source.as_bytes()
                );
            }
        }
    }
}

#[test]
fn s1451_cli_invalid_utf8_analysis_is_incomplete_and_preserves_source() {
    let fixture = Fixture::new("invalid-utf8");
    let source = b"\xffconst value = 1;\n";
    for extension in ["js", "ts"] {
        let file = format!("invalid.{extension}");
        let path = fixture.0.join(&file);
        std::fs::write(&path, source).expect("malformed source");
        for format in ["json", "sonar"] {
            let output = fixture.run(&["analyze", &file, "--format", format]);
            assert_eq!(output.status.code(), Some(2));
            if format == "json" {
                let report: serde_json::Value =
                    serde_json::from_slice(&output.stdout).expect("incomplete JSON");
                assert_eq!(report["project"]["complete"], false);
            }
            assert_eq!(std::fs::read(&path).expect("source readback"), source);
        }
    }
}

#[test]
fn s1451_cli_unavailable_and_malformed_fix_selections_refuse_without_writing() {
    let fixture = Fixture::new("refusal");
    let source = b"const value = 1;\n";
    for (extension, language) in [("js", "javascript"), ("ts", "typescript")] {
        let file = format!("case.{extension}");
        let path = fixture.0.join(&file);
        let rule = format!("{language}:S1451");
        let unavailable = format!("{rule}=s1451-add-or-update-license-header");
        std::fs::write(&path, source).expect("fixture source");
        for mode in ["--diff", "--apply"] {
            let output = fixture.run(&["fix", &file, mode, "--json", "--suggestion", &unavailable]);
            assert_eq!(output.status.code(), Some(1));
            assert!(String::from_utf8_lossy(&output.stderr).contains("is unavailable"));
            let report: serde_json::Value =
                serde_json::from_slice(&output.stdout).expect("refused fix JSON");
            assert_eq!(report["files"], serde_json::json!([]));
            assert_eq!(std::fs::read(&path).expect("source readback"), source);

            let malformed = fixture.run(&["fix", &file, mode, "--suggestion", &rule]);
            assert_eq!(malformed.status.code(), Some(2));
            assert!(String::from_utf8_lossy(&malformed.stderr).contains("expected RULE=ACTION_ID"));
            assert_eq!(std::fs::read(&path).expect("source readback"), source);
        }
        let analysis = fixture.run(&["analyze", &file, "--format", "json"]);
        assert!(analysis.status.success(), "{analysis:?}");
        let report: serde_json::Value =
            serde_json::from_slice(&analysis.stdout).expect("retained finding JSON");
        let issues = report["files"][0]["issues"].as_array().expect("issues");
        assert_eq!(
            issues
                .iter()
                .filter(|issue| issue["rule_key"] == rule)
                .count(),
            1
        );
        let header = issues
            .iter()
            .find(|issue| issue["rule_key"] == rule)
            .expect("header");
        assert!(header.get("fix").is_none());
        assert!(header.get("alternatives").is_none());
    }
}
