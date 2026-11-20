use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::{Value, json};

// Verified from the retained Sonar Python 5.31.0.36502 plugin and 18 real
// Requests, Werkzeug, and Click findings. S1309 tracks suppressions for review.
const S1309_MESSAGE: &str =
    "Is 'noqa' used to exclude false-positive or to hide real quality flaw?";
const NOSONAR_MESSAGE: &str =
    "Is #NOSONAR used to exclude false-positive or to hide real quality flaw?";
const S7632_MESSAGE: &str = "Fix the syntax of this issue suppression comment.";

struct Fixture(PathBuf);

impl Fixture {
    fn new(label: &str) -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-s1309-{label}-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("fixture directory");
        Self(path)
    }

    fn analyze(&self, name: &str, source: &str, format: &str) -> Output {
        let path = self.0.join(name);
        std::fs::write(&path, source).expect("fixture source");
        let output = Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args(["analyze", name, "--profile", "strict", "--format", format])
            .output()
            .expect("run hoonarqube");
        assert_eq!(
            std::fs::read_to_string(&path).expect("source readback"),
            source,
            "analysis must preserve source"
        );
        output
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

type ExpectedFinding = (&'static str, &'static str, u32, u32);

struct Case {
    name: &'static str,
    source: &'static str,
    findings: Vec<ExpectedFinding>,
}

fn suppression_cases() -> Vec<Case> {
    vec![
        Case {
            name: "single.py",
            source: "\"\"\"Suppression control.\"\"\"\n# noqa\n",
            findings: vec![("python:S1309", S1309_MESSAGE, 2, 6)],
        },
        Case {
            name: "multiple.py",
            source: "\"\"\"Suppression tracking controls.\"\"\"\n# noqa\n# noqa: E501,F841\n#NOQA isort:skip\n# noqa: E501 # noqa: F841\n",
            findings: vec![
                ("python:S1309", S1309_MESSAGE, 2, 6),
                ("python:S1309", S1309_MESSAGE, 3, 17),
                ("python:S1309", S1309_MESSAGE, 4, 16),
                ("python:S1309", S1309_MESSAGE, 5, 25),
            ],
        },
        Case {
            name: "mixed.py",
            source: "\"\"\"Mixed suppression controls.\"\"\"\n# NOSONAR # noqa: E501\n# nosec B101 # noqa\n# nosonar\n",
            findings: vec![
                ("python:NoSonar", NOSONAR_MESSAGE, 2, 22),
                ("python:S1309", S1309_MESSAGE, 2, 22),
                ("python:S1309", S1309_MESSAGE, 3, 19),
            ],
        },
        Case {
            name: "malformed_suppressions.py",
            source: "\"\"\"Malformed suppression controls.\"\"\"\n# NOSONAR(\n# noqa: E501,,F841\n",
            findings: vec![
                ("python:NoSonar", NOSONAR_MESSAGE, 2, 10),
                ("python:S7632", S7632_MESSAGE, 2, 10),
                ("python:S1309", S1309_MESSAGE, 3, 18),
                ("python:S7632", S7632_MESSAGE, 3, 18),
            ],
        },
        Case {
            name: "nosonar_case.py",
            source: "\"\"\"Case boundaries.\"\"\"\n# nosonar\n# NOSONAR\n",
            findings: vec![("python:NoSonar", NOSONAR_MESSAGE, 3, 9)],
        },
    ]
}

#[test]
fn python_s1309_native_json_matches_reference_message_and_preserves_suppressions() {
    for case in suppression_cases() {
        let fixture = Fixture::new("native");
        let output = fixture.analyze(case.name, case.source, "json");
        assert!(output.status.success(), "{}: {output:?}", case.name);
        let report: Value = serde_json::from_slice(&output.stdout).expect("native JSON");
        assert_eq!(report["project"]["complete"], true);
        assert_eq!(report["project"]["files"][0]["status"], "complete");
        assert_eq!(report["files"][0]["path"], case.name);
        let expected: Vec<_> = case
            .findings
            .iter()
            .map(|(rule, message, line, end_column)| {
                json!({
                    "rule_key": rule,
                    "message": message,
                    "range": {
                        "start": { "line": line, "column": 0 },
                        "end": { "line": line, "column": end_column }
                    }
                })
            })
            .collect();
        assert_eq!(
            report["files"][0]["issues"],
            json!(expected),
            "{}",
            case.name
        );
    }
}

#[test]
fn python_s1309_generic_sonar_export_matches_reference_message_and_preserves_suppressions() {
    for case in suppression_cases() {
        let fixture = Fixture::new("sonar");
        let output = fixture.analyze(case.name, case.source, "sonar");
        assert!(output.status.success(), "{}: {output:?}", case.name);
        let report: Value = serde_json::from_slice(&output.stdout).expect("Sonar Generic JSON");
        let expected: Vec<_> = case
            .findings
            .iter()
            .map(|(rule, message, line, end_column)| {
                json!({
                    "ruleId": rule,
                    "primaryLocation": {
                        "filePath": case.name,
                        "message": message,
                        "textRange": {
                            "startLine": line, "startColumn": 0,
                            "endLine": line, "endColumn": end_column
                        }
                    }
                })
            })
            .collect();
        assert_eq!(report["issues"], json!(expected), "{}", case.name);
    }
}

#[test]
fn python_s1309_clean_literals_and_existing_nosec_boundary_remain_clean() {
    let cases = [
        (
            "clean.py",
            "\"\"\"A clean control.\"\"\"\n# Ordinary comment.\n",
        ),
        (
            "literal.py",
            "\"\"\"A literal string containing # noqa and # NOSONAR.\"\"\"\n",
        ),
        (
            "nosec_only.py",
            "\"\"\"Existing nosec boundary.\"\"\"\n# nosec B101\n",
        ),
    ];
    for (name, source) in cases {
        for format in ["json", "sonar"] {
            let fixture = Fixture::new("clean");
            let output = fixture.analyze(name, source, format);
            assert!(output.status.success(), "{name}/{format}: {output:?}");
            let report: Value = serde_json::from_slice(&output.stdout).expect("clean JSON");
            if format == "json" {
                assert_eq!(report["project"]["complete"], true);
                assert_eq!(report["files"][0]["issues"], json!([]));
            } else {
                assert_eq!(report["issues"], json!([]));
            }
        }
    }
}

#[test]
fn python_s1309_message_change_preserves_malformed_source_exit_two() {
    let fixture = Fixture::new("broken");
    let source = "\"\"\"Invalid syntax must remain incomplete.\"\"\"\ndef broken(\n";
    for format in ["json", "sonar"] {
        let output = fixture.analyze("broken.py", source, format);
        assert_eq!(output.status.code(), Some(2), "{format}: {output:?}");
        let report: Value = serde_json::from_slice(&output.stdout).expect("incomplete JSON");
        if format == "json" {
            assert_eq!(report["project"]["complete"], false);
            assert_eq!(report["project"]["files"][0]["status"], "failed");
        }
    }
}
