use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::{Value, json};

// Pinned SonarQube 26.9.0.129388 / Python 5.31.0.36502 scanner observations.
// Expected messages and whole-comment ranges were captured independently.
const NOSEC_MESSAGE: &str =
    "Is 'nosec' used to exclude false-positive or to hide real security issue?";
const NOQA_MESSAGE: &str = "Is 'noqa' used to exclude false-positive or to hide real quality flaw?";

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("hoonarqube-nosec-{}-{id}", std::process::id()));
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
            std::fs::read_to_string(path).expect("source readback"),
            source
        );
        output
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn assert_directive(name: &str, comment: &str, message: &str, end_offset: u32) {
    let fixture = Fixture::new();
    let filename = format!("{name}.py");
    let source = format!("\"\"\"Suppression directive control.\"\"\"\nvalue = 1 {comment}\n");
    for format in ["json", "sonar"] {
        let output = fixture.analyze(&filename, &source, format);
        assert!(output.status.success(), "{name}/{format}: {output:?}");
        let report: Value = serde_json::from_slice(&output.stdout).expect("report JSON");
        if format == "json" {
            assert_eq!(report["project"]["complete"], true);
            assert_eq!(report["project"]["files"][0]["status"], "complete");
            assert_eq!(report["files"][0]["path"], filename);
            let findings: Vec<_> = report["files"][0]["issues"]
                .as_array()
                .expect("issues")
                .iter()
                .filter(|issue| issue["rule_key"] == "python:S1309")
                .map(|issue| json!({"message": issue["message"], "range": issue["range"]}))
                .collect();
            assert_eq!(
                findings,
                vec![json!({
                    "message": message,
                    "range": {
                    "start": {"line": 2, "column": 10},
                    "end": {"line": 2, "column": end_offset}
                    }
                })],
                "{name}/{format}"
            );
        } else {
            let findings: Vec<_> = report["issues"]
                .as_array()
                .expect("Sonar issues")
                .iter()
                .filter(|issue| issue["ruleId"] == "python:S1309")
                .cloned()
                .collect();
            assert_eq!(
                findings,
                vec![json!({
                    "ruleId": "python:S1309",
                    "primaryLocation": {
                        "filePath": filename,
                        "message": message,
                        "textRange": {
                            "startLine": 2, "startColumn": 10,
                            "endLine": 2, "endColumn": end_offset
                        }
                    }
                })],
                "{name}/{format}"
            );
        }
    }
}

#[test]
fn python_s1309_nosec_native_and_sonar_match_reference_directives() {
    for (name, comment, message, end_offset) in [
        ("bare", "# nosec", NOSEC_MESSAGE, 17),
        ("compact", "#nosec", NOSEC_MESSAGE, 16),
        ("uppercase", "# NOSEC", NOSEC_MESSAGE, 17),
        ("mixed_case", "# NoSeC", NOSEC_MESSAGE, 17),
        ("tab", "#\tnosec", NOSEC_MESSAGE, 17),
        ("formfeed", "#\u{000c}nosec", NOSEC_MESSAGE, 17),
        ("vertical_tab", "#\u{000b}nosec", NOSEC_MESSAGE, 17),
        ("colon", "# nosec:", NOSEC_MESSAGE, 18),
        ("rule", "# nosec B101", NOSEC_MESSAGE, 22),
        ("rules", "# nosec: B101, S1234 reason", NOSEC_MESSAGE, 37),
        (
            "reason",
            "# nosec because of foo, bar, and baz",
            NOSEC_MESSAGE,
            46,
        ),
        ("period", "# nosec.", NOSEC_MESSAGE, 18),
        ("hyphen", "# nosec-because", NOSEC_MESSAGE, 25),
        ("parentheses", "# nosec(reason)", NOSEC_MESSAGE, 25),
        ("comma", "# nosec,", NOSEC_MESSAGE, 18),
        (
            "malformed_rule_list",
            "# nosec B101, foo",
            NOSEC_MESSAGE,
            27,
        ),
        ("empty_rule_list", "# nosec B101,", NOSEC_MESSAGE, 23),
        ("nested_hash", "# explanation ## nosec", NOSEC_MESSAGE, 32),
    ] {
        assert_directive(name, comment, message, end_offset);
    }
}

#[test]
fn python_s1309_first_valid_inline_directive_selects_one_message() {
    for (name, comment, message, end_offset) in [
        ("nosec_before_noqa", "# nosec # noqa", NOSEC_MESSAGE, 24),
        ("noqa_before_nosec", "# noqa # nosec", NOQA_MESSAGE, 24),
        (
            "invalid_noqa_before_nosec",
            "# noqax # nosec",
            NOSEC_MESSAGE,
            25,
        ),
        (
            "uppercase_noqa_before_nosec",
            "# NOQA # nosec",
            NOSEC_MESSAGE,
            24,
        ),
        ("nosec_twice", "# nosec # nosec", NOSEC_MESSAGE, 25),
        (
            "nosec_before_nosonar",
            "# nosec # NOSONAR",
            NOSEC_MESSAGE,
            27,
        ),
        (
            "noqa_text_in_reason",
            "# nosec reason mentions noqa",
            NOSEC_MESSAGE,
            38,
        ),
    ] {
        assert_directive(name, comment, message, end_offset);
    }
}

#[test]
fn python_s1309_nosec_prefix_and_literal_controls_stay_clean() {
    for (name, source) in [
        (
            "word_suffix",
            "\"\"\"Suppression directive control.\"\"\"\nvalue = 1 # nosecurity\n",
        ),
        (
            "underscore_suffix",
            "\"\"\"Suppression directive control.\"\"\"\nvalue = 1 # nosec_reason\n",
        ),
        (
            "digit_suffix",
            "\"\"\"Suppression directive control.\"\"\"\nvalue = 1 # nosec1\n",
        ),
        (
            "letter_suffix",
            "\"\"\"Suppression directive control.\"\"\"\nvalue = 1 # nosecX\n",
        ),
        (
            "prefix_prose",
            "\"\"\"Suppression directive control.\"\"\"\nvalue = 1 # please nosec this\n",
        ),
        (
            "prefix_word",
            "\"\"\"Suppression directive control.\"\"\"\nvalue = 1 # xnosec\n",
        ),
        (
            "quoted",
            "\"\"\"Suppression directive control.\"\"\"\nvalue = 1 # \"nosec\"\n",
        ),
        (
            "escaped_prefix",
            "\"\"\"Suppression directive control.\"\"\"\nvalue = 1 # \\nosec\n",
        ),
        (
            "unicode_space",
            "\"\"\"Suppression directive control.\"\"\"\nvalue = 1 #\u{00a0}nosec\n",
        ),
        (
            "ordinary",
            "\"\"\"Suppression directive control.\"\"\"\nvalue = 1 # ordinary explanation\n",
        ),
        (
            "empty",
            "\"\"\"Suppression directive control.\"\"\"\nvalue = 1 #\n",
        ),
        (
            "literal",
            "\"\"\"Literal control.\"\"\"\nvalue = \"# nosec\"\n",
        ),
        ("docstring", "\"\"\"# nosec B101\"\"\"\n"),
    ] {
        for format in ["json", "sonar"] {
            let fixture = Fixture::new();
            let output = fixture.analyze(&format!("{name}.py"), source, format);
            assert!(output.status.success(), "{name}/{format}: {output:?}");
            let report: Value = serde_json::from_slice(&output.stdout).expect("clean JSON");
            let count = if format == "json" {
                assert_eq!(report["project"]["complete"], true);
                report["files"][0]["issues"]
                    .as_array()
                    .expect("issues")
                    .iter()
                    .filter(|issue| issue["rule_key"] == "python:S1309")
                    .count()
            } else {
                report["issues"]
                    .as_array()
                    .expect("Sonar issues")
                    .iter()
                    .filter(|issue| issue["ruleId"] == "python:S1309")
                    .count()
            };
            assert_eq!(count, 0, "{name}/{format}");
        }
    }
}

#[test]
fn python_s1309_nosec_malformed_source_stays_incomplete() {
    let fixture = Fixture::new();
    let source = "\"\"\"Broken source control.\"\"\"\nvalue = ( # nosec\n";
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
