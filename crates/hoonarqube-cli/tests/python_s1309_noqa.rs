use std::path::PathBuf;
use std::process::Command;

use serde_json::{Value, json};

// Qualified against the retained Sonar Python 5.31.0.36502 parser. The first
// three negative comments also have complete independent real-scanner evidence.
const NOQA_MESSAGE: &str = "Is 'noqa' used to exclude false-positive or to hide real quality flaw?";
const NOSEC_MESSAGE: &str =
    "Is 'nosec' used to exclude false-positive or to hide real security issue?";
const NOSONAR_MESSAGE: &str =
    "Is #NOSONAR used to exclude false-positive or to hide real quality flaw?";
const S7632_MESSAGE: &str = "Fix the syntax of this issue suppression comment.";

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-noqa-boundaries-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("fixture directory");
        Self(path)
    }

    fn assert_source(
        &self,
        name: &str,
        source: &str,
        complete: bool,
        expected: &[(&str, &str, u32)],
    ) {
        let filename = format!("{name}.py");
        let path = self.0.join(&filename);
        for format in ["json", "sonar"] {
            std::fs::write(&path, source).expect("fixture source");
            let output = Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
                .current_dir(&self.0)
                .args([
                    "analyze",
                    &filename,
                    "--profile",
                    "strict",
                    "--format",
                    format,
                ])
                .output()
                .expect("run hoonarqube");
            assert_eq!(
                output.status.code(),
                Some(if complete { 0 } else { 2 }),
                "{name}/{format}: {output:?}"
            );
            assert_eq!(
                std::fs::read_to_string(&path).expect("source readback"),
                source,
                "{name}/{format} must preserve input"
            );
            let report: Value = serde_json::from_slice(&output.stdout).expect("report JSON");
            let findings = suppression_findings(
                &report,
                &filename,
                format,
                complete,
                expected.iter().any(|(rule, _, _)| *rule == "python:S1309"),
            );
            let expected: Vec<Value> = expected
                .iter()
                .map(|(rule, message, end)| {
                    json!({
                        "rule": rule, "message": message,
                        "startLine": 2, "startColumn": 10,
                        "endLine": 2, "endColumn": end
                    })
                })
                .collect();
            assert_eq!(findings, expected, "{name}/{format}");
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn suppression_findings(
    report: &Value,
    filename: &str,
    format: &str,
    complete: bool,
    expected_s1309: bool,
) -> Vec<Value> {
    if format == "json" {
        assert_eq!(report["project"]["complete"], complete);
        assert_eq!(
            report["project"]["files"][0]["status"],
            if complete { "complete" } else { "failed" }
        );
        assert_eq!(report["files"][0]["path"], filename);
        report["files"][0]["issues"]
            .as_array()
            .expect("native issues")
            .iter()
            .filter(|issue| {
                matches!(
                    issue["rule_key"].as_str(),
                    Some("python:S1309" | "python:NoSonar" | "python:S7632")
                )
            })
            .map(|issue| {
                json!({
                    "rule": issue["rule_key"],
                    "message": issue["message"],
                    "startLine": issue["range"]["start"]["line"],
                    "startColumn": issue["range"]["start"]["column"],
                    "endLine": issue["range"]["end"]["line"],
                    "endColumn": issue["range"]["end"]["column"]
                })
            })
            .collect()
    } else {
        assert_eq!(
            report["rules"]
                .as_array()
                .expect("Generic rule definitions")
                .iter()
                .filter(|rule| rule["id"] == "python:S1309")
                .count(),
            usize::from(expected_s1309),
            "definition follows the presence of S1309"
        );
        report["issues"]
            .as_array()
            .expect("Generic issues")
            .iter()
            .filter(|issue| {
                matches!(
                    issue["ruleId"].as_str(),
                    Some("python:S1309" | "python:NoSonar" | "python:S7632")
                )
            })
            .map(|issue| {
                let location = &issue["primaryLocation"];
                assert_eq!(location["filePath"], filename);
                json!({
                    "rule": issue["ruleId"],
                    "message": location["message"],
                    "startLine": location["textRange"]["startLine"],
                    "startColumn": location["textRange"]["startColumn"],
                    "endLine": location["textRange"]["endLine"],
                    "endColumn": location["textRange"]["endColumn"]
                })
            })
            .collect()
    }
}

fn assert_comment(name: &str, comment: &str, expected: &[(&str, &str, u32)]) {
    let source = format!("\"\"\"Suppression directive control.\"\"\"\nvalue = 1 {comment}\n");
    Fixture::new().assert_source(name, &source, true, expected);
}

#[test]
fn python_s1309_noqa_invalid_case_prefix_and_prose_remain_clean() {
    for (name, comment) in [
        ("noqa_upper", "# NOQA"),
        ("noqa_substring", "# noqax"),
        ("noqa_prose", "# mention noqa"),
        ("mixed_case", "# NoQa"),
        ("upper_with_reason", "#NOQA isort:skip"),
        ("word_suffix", "# noqal"),
        ("digit_suffix", "# noqa1"),
        ("underscore_suffix", "# noqa_reason"),
        ("period", "# noqa."),
        ("hyphen", "# noqa-because"),
        ("comma", "# noqa,"),
        ("parentheses", "# noqa(reason)"),
        ("prefix_word", "# xnoqa"),
        ("quoted", "# \"noqa\""),
        ("escaped_prefix", "# \\noqa"),
    ] {
        assert_comment(name, comment, &[]);
    }
}

#[test]
fn python_s1309_noqa_valid_directives_match_reference_and_preserve_ranges() {
    for (name, comment, end) in [
        ("compact", "#noqa", 15),
        ("bare", "# noqa", 16),
        ("tab", "#\tnoqa", 16),
        ("formfeed", "#\u{000c}noqa", 16),
        ("vertical_tab", "#\u{000b}noqa", 16),
        ("colon", "# noqa:", 17),
        ("rule", "# noqa: E501", 22),
        ("semicolon", "# noqa; reason", 24),
        ("space_before_colon", "# noqa : E501", 23),
        ("lowercase_rule", "# noqa: e501", 22),
        ("trailing_prose", "# noqa isort:skip", 27),
        ("nested_hash", "# explanation ## noqa", 31),
        ("noqa_twice", "# noqa # noqa", 23),
        ("prose_then_valid", "# mention noqa # noqa", 31),
        ("noqa_then_nosec", "# noqa # nosec", 24),
    ] {
        assert_comment(name, comment, &[("python:S1309", NOQA_MESSAGE, end)]);
    }
}

#[test]
fn python_s1309_noqa_boundaries_preserve_nosec_nosonar_and_s7632() {
    for (name, comment, end) in [
        ("upper_then_nosec", "# NOQA # nosec", 24),
        ("substring_then_nosec", "# noqax # nosec", 25),
        ("nosec_then_noqa", "# nosec # noqa", 24),
        (
            "nosec_reason_mentions_noqa",
            "# nosec reason mentions noqa",
            38,
        ),
    ] {
        assert_comment(name, comment, &[("python:S1309", NOSEC_MESSAGE, end)]);
    }
    assert_comment(
        "nosonar_then_upper",
        "# NOSONAR # NOQA",
        &[("python:NoSonar", NOSONAR_MESSAGE, 26)],
    );
    assert_comment(
        "broken_nosonar_then_upper",
        "# NOSONAR( # NOQA",
        &[
            ("python:NoSonar", NOSONAR_MESSAGE, 27),
            ("python:S7632", S7632_MESSAGE, 27),
        ],
    );
    assert_comment(
        "malformed_noqa_rules",
        "# noqa: E501,,F841",
        &[
            ("python:S1309", NOQA_MESSAGE, 28),
            ("python:S7632", S7632_MESSAGE, 28),
        ],
    );
    assert_comment(
        "malformed_nosec_rules",
        "# nosec B101, foo",
        &[
            ("python:S1309", NOSEC_MESSAGE, 27),
            ("python:S7632", S7632_MESSAGE, 27),
        ],
    );
}

#[test]
fn python_s1309_noqa_literals_remain_clean() {
    for (name, source) in [
        (
            "literal",
            "\"\"\"Literal control.\"\"\"\nvalue = \"# noqa\"\n",
        ),
        ("docstring", "\"\"\"# noqa\"\"\"\n"),
    ] {
        Fixture::new().assert_source(name, source, true, &[]);
    }
}

#[test]
fn python_s1309_noqa_boundaries_preserve_malformed_recovery() {
    for (name, comment, expected) in [
        (
            "broken_upper",
            "# NOQA",
            vec![("python:S1309", NOQA_MESSAGE, 16)],
        ),
        (
            "broken_substring",
            "# noqax",
            vec![("python:S1309", NOQA_MESSAGE, 17)],
        ),
        (
            "broken_valid_noqa",
            "# noqa",
            vec![("python:S1309", NOQA_MESSAGE, 16)],
        ),
        ("broken_nosec", "# nosec", vec![]),
    ] {
        let source = format!("\"\"\"Broken source control.\"\"\"\nvalue = ( {comment}\n");
        Fixture::new().assert_source(name, &source, false, &expected);
    }
}
