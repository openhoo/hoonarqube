use std::path::PathBuf;
use std::process::Command;

use serde_json::{Value, json};

// The exact message and keyword range are independently scanner-backed for
// the ordinary assignment and Werkzeug witness with Sonar Python 5.31.0.36502.
// Other boundaries are native controls interpreted against that check's bytecode.
const MESSAGE: &str = "Define function instead of this lambda assignment statement.";
const ASSIGNMENTS: [(&str, &str, u32, u32); 6] = [
    ("ordinary", "handler = lambda event: str(event)\n", 1, 10),
    (
        "annotated",
        "handler: object = lambda event: str(event)\n",
        1,
        18,
    ),
    (
        "chained",
        "first = second = lambda event: str(event)\n",
        1,
        17,
    ),
    (
        "multiline",
        "handler = (\n    lambda event: (\n        str(event)\n    )\n)\n",
        2,
        4,
    ),
    ("unicode", "é = lambda event: str(event)\n", 1, 4),
    (
        "attribute",
        "self.is_allowed = lambda x: not fnmatch(x, disallow)\n",
        1,
        18,
    ),
];

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-s6661-message-range-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("fixture directory");
        Self(path)
    }

    fn analyze(&self, name: &str, source: &str, profile: &str, format: &str, exit: i32) -> Value {
        let filename = format!("{name}.py");
        let path = self.0.join(&filename);
        std::fs::write(&path, source).expect("fixture source");
        let output = Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args([
                "analyze",
                &filename,
                "--profile",
                profile,
                "--format",
                format,
            ])
            .output()
            .expect("run hoonarqube");
        assert_eq!(
            output.status.code(),
            Some(exit),
            "{name}/{profile}/{format}: {output:?}"
        );
        assert_eq!(
            std::fs::read_to_string(path).expect("source readback"),
            source
        );
        let report: Value = serde_json::from_slice(&output.stdout).expect("report JSON");
        if format == "json" {
            assert_eq!(report["project"]["complete"], exit == 0);
            assert_eq!(report["project"]["files"][0]["path"], filename);
            assert_eq!(
                report["project"]["files"][0]["status"],
                if exit == 0 { "complete" } else { "failed" }
            );
        }
        report
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn native_targets(report: &Value, name: &str) -> Vec<Value> {
    assert_eq!(report["files"][0]["path"], format!("{name}.py"));
    report["files"][0]["issues"]
        .as_array()
        .expect("native issues")
        .iter()
        .filter(|issue| issue["rule_key"] == "python:S6661")
        .cloned()
        .collect()
}

fn generic_targets(report: &Value, name: &str) -> Vec<Value> {
    report["issues"]
        .as_array()
        .expect("Generic issues")
        .iter()
        .filter(|issue| issue["ruleId"] == "python:S6661")
        .map(|issue| {
            assert_eq!(issue["primaryLocation"]["filePath"], format!("{name}.py"));
            issue.clone()
        })
        .collect()
}

#[test]
fn python_s6661_native_messages_match_reference() {
    let fixture = Fixture::new();
    for (name, source, _, _) in ASSIGNMENTS {
        for profile in ["strict", "sonar-parity"] {
            let report = fixture.analyze(name, source, profile, "json", 0);
            let issues = native_targets(&report, name);
            assert_eq!(issues.len(), 1, "{name}/{profile}");
            assert_eq!(issues[0]["message"], MESSAGE, "{name}/{profile}");
        }
    }
}

#[test]
fn python_s6661_generic_messages_match_reference() {
    let fixture = Fixture::new();
    for (name, source, _, _) in ASSIGNMENTS {
        for profile in ["strict", "sonar-parity"] {
            let report = fixture.analyze(name, source, profile, "sonar", 0);
            let issues = generic_targets(&report, name);
            assert_eq!(issues.len(), 1, "{name}/{profile}");
            assert_eq!(
                issues[0]["primaryLocation"]["message"], MESSAGE,
                "{name}/{profile}"
            );
        }
    }
}

#[test]
fn python_s6661_native_ranges_cover_only_the_keyword() {
    let fixture = Fixture::new();
    for (name, source, line, column) in ASSIGNMENTS {
        for profile in ["strict", "sonar-parity"] {
            let report = fixture.analyze(name, source, profile, "json", 0);
            let issues = native_targets(&report, name);
            assert_eq!(issues.len(), 1, "{name}/{profile}");
            assert_eq!(
                issues[0]["range"],
                json!({
                    "start": { "line": line, "column": column },
                    "end": { "line": line, "column": column + 6 }
                }),
                "{name}/{profile}"
            );
            assert!(issues[0].get("fix").is_none());
            assert!(issues[0].get("flows").is_none());
            assert!(issues[0].get("alternatives").is_none());
        }
    }
}

#[test]
fn python_s6661_generic_ranges_cover_only_the_keyword() {
    let fixture = Fixture::new();
    for (name, source, line, column) in ASSIGNMENTS {
        for profile in ["strict", "sonar-parity"] {
            let report = fixture.analyze(name, source, profile, "sonar", 0);
            let issues = generic_targets(&report, name);
            assert_eq!(issues.len(), 1, "{name}/{profile}");
            assert_eq!(
                issues[0]["primaryLocation"]["textRange"],
                json!({
                    "startLine": line, "startColumn": column,
                    "endLine": line, "endColumn": column + 6
                }),
                "{name}/{profile}"
            );
        }
    }
}

#[test]
fn python_s6661_generic_rule_definition_is_preserved() {
    let fixture = Fixture::new();
    for profile in ["strict", "sonar-parity"] {
        let report = fixture.analyze("ordinary", ASSIGNMENTS[0].1, profile, "sonar", 0);
        let rules: Vec<&Value> = report["rules"]
            .as_array()
            .expect("rule definitions")
            .iter()
            .filter(|rule| rule["id"] == "python:S6661")
            .collect();
        assert_eq!(
            rules,
            vec![&json!({
                "cleanCodeAttribute": "CONVENTIONAL",
                "description": "Hoonarqube finding for `python:S6661`.",
                "engineId": "hoonarqube", "id": "python:S6661",
                "impacts": [{ "severity": "LOW", "softwareQuality": "MAINTAINABILITY" }],
                "name": "python:S6661", "severity": "MINOR", "type": "CODE_SMELL"
            })]
        );
    }
}

#[test]
fn python_s6661_clean_controls_remain_target_free() {
    let fixture = Fixture::new();
    for (name, source) in [
        ("named", "def handler(event):\n    return str(event)\n"),
        ("argument", "values = map(lambda event: str(event), [])\n"),
        ("string", "text = \"lambda event: str(event)\"\n"),
        ("annotation", "handler: object\n"),
    ] {
        for profile in ["strict", "sonar-parity"] {
            let native = fixture.analyze(name, source, profile, "json", 0);
            let generic = fixture.analyze(name, source, profile, "sonar", 0);
            assert!(native_targets(&native, name).is_empty(), "{name}/{profile}");
            assert!(
                generic_targets(&generic, name).is_empty(),
                "{name}/{profile}"
            );
        }
    }
}

#[test]
fn python_s6661_malformed_input_retains_refusal_and_diagnostics() {
    let fixture = Fixture::new();
    for profile in ["strict", "sonar-parity"] {
        let native = fixture.analyze("broken", "def f(:\n    pass\n", profile, "json", 2);
        let generic = fixture.analyze("broken", "def f(:\n    pass\n", profile, "sonar", 2);
        assert!(native_targets(&native, "broken").is_empty());
        assert!(generic_targets(&generic, "broken").is_empty());
        assert_eq!(
            native["project"]["files"][0]["reason"],
            "syntax tree contains recovered or missing nodes"
        );
        assert!(
            native["files"][0]["issues"]
                .as_array()
                .expect("recovered issues")
                .iter()
                .any(|issue| issue["rule_key"] == "python:ParsingError")
        );
    }
}
