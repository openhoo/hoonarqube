use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-python-empty-suites-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("fixture directory");
        Self(path)
    }

    fn analyze(&self, source: &str, profile: &str, format: &str, valid: bool) -> Value {
        std::fs::write(self.0.join("case.py"), source).expect("write source");
        let output = Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args([
                "analyze",
                "case.py",
                "--profile",
                profile,
                "--format",
                format,
            ])
            .output()
            .expect("run hoonarqube");
        assert_eq!(
            output.status.code(),
            Some(if valid { 0 } else { 2 }),
            "{output:?}"
        );
        assert_eq!(output.stderr.is_empty(), valid, "{output:?}");
        let report: Value = serde_json::from_slice(&output.stdout).expect("structured report");
        if !valid && profile == "sonar-parity" {
            assert_eq!(report["parity"]["completeness"], "incomplete");
        }
        if format == "json" {
            assert_eq!(report["project"]["complete"], valid);
            assert_eq!(report["project"]["files"][0]["status"] == "complete", valid);
            if !valid {
                assert!(
                    !report["project"]["warnings"]
                        .as_array()
                        .expect("warnings")
                        .is_empty()
                );
                assert_eq!(report["project"]["files"][0]["status"], "failed");
            }
        }
        assert_eq!(
            std::fs::read_to_string(self.0.join("case.py")).expect("source readback"),
            source
        );
        report
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("fixture cleanup");
    }
}

fn findings<'a>(report: &'a Value, format: &str, rule: &str) -> Vec<&'a Value> {
    let (issues, key) = if format == "json" {
        (&report["files"][0]["issues"], "rule_key")
    } else {
        (&report["issues"], "ruleId")
    };
    issues
        .as_array()
        .expect("issue array")
        .iter()
        .filter(|issue| issue[key] == rule)
        .collect()
}

const EMPTY_SUITES: &[&str] = &[
    "if (\n",
    "if condition:\n",
    "if condition:\nelse:\n",
    "if condition:\n    pass\nelif other:\n",
    "if condition:\n    pass\nelse:\n",
    "if condition:\nelse:\n    execute()\n    update()\n",
    "try:\n    work()\nexcept First:\n",
    "try:\n    work()\nexcept First:\nexcept Second:\n    execute()\n    update()\n",
];

fn assert_recovered_empty_suites(format: &str) {
    let fixture = Fixture::new();
    for source in EMPTY_SUITES {
        for profile in ["strict", "sonar-parity"] {
            let report = fixture.analyze(source, profile, format, false);
            assert!(!findings(&report, format, "python:ParsingError").is_empty());
            for rule in ["python:S1871", "python:S3923"] {
                assert!(
                    findings(&report, format, rule).is_empty(),
                    "{source}/{profile}/{format}"
                );
            }
        }
    }
}

#[test]
fn native_recovered_empty_suites_report_incomplete_without_panicking() {
    assert_recovered_empty_suites("json");
}

#[test]
fn generic_recovered_empty_suites_report_parse_errors_without_panicking() {
    assert_recovered_empty_suites("sonar");
}

#[test]
fn real_duplicate_branches_survive_an_empty_middle_suite() {
    let source = "if condition:\n    execute()\n    update()\nelif other:\nelse:\n    execute()\n    update()\n";
    let fixture = Fixture::new();
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            let report = fixture.analyze(source, profile, format, false);
            let issues = findings(&report, format, "python:S1871");
            assert_eq!(issues.len(), 1);
            let location = if format == "json" {
                &issues[0]["range"]
            } else {
                &issues[0]["primaryLocation"]["textRange"]
            };
            if format == "json" {
                assert_eq!(location["start"]["line"], 6);
                assert_eq!(location["start"]["column"], 4);
                assert_eq!(location["end"]["line"], 7);
                assert_eq!(location["end"]["column"], 12);
                assert_eq!(
                    issues[0]["message"],
                    "Either merge this branch with the identical one on line \"2\" or change one of the implementations."
                );
            } else {
                assert_eq!(location["startLine"], 6);
                assert_eq!(location["startColumn"], 4);
                assert_eq!(location["endLine"], 7);
                assert_eq!(location["endColumn"], 12);
                assert_eq!(
                    issues[0]["primaryLocation"]["message"],
                    "Either merge this branch with the identical one on line \"2\" or change one of the implementations."
                );
            }
            assert!(!findings(&report, format, "python:ParsingError").is_empty());
            assert!(findings(&report, format, "python:S3923").is_empty());
        }
    }
}

#[test]
fn valid_duplicate_identical_and_clean_branch_controls_remain_complete() {
    let controls = [
        (
            "if condition:\n    execute()\n    update()\nelif other:\n    execute()\n    update()\n",
            1,
            0,
        ),
        ("if condition:\n    execute()\nelse:\n    execute()\n", 0, 1),
        ("if condition:\n    execute()\nelse:\n    update()\n", 0, 0),
        (
            "if condition:\n    execute()\nelif other:\n    execute()\n",
            0,
            0,
        ),
        (
            "try:\n    work()\nexcept First:\n    execute()\n    update()\nexcept Second:\n    execute()\n    update()\n",
            1,
            0,
        ),
    ];
    let fixture = Fixture::new();
    for (source, duplicates, identical) in controls {
        for profile in ["strict", "sonar-parity"] {
            for format in ["json", "sonar"] {
                let report = fixture.analyze(source, profile, format, true);
                assert_eq!(findings(&report, format, "python:S1871").len(), duplicates);
                assert_eq!(findings(&report, format, "python:S3923").len(), identical);
                assert!(findings(&report, format, "python:ParsingError").is_empty());
            }
        }
    }
}
