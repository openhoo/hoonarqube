use std::path::PathBuf;
use std::process::Command;

use serde_json::{Value, json};

// The retained real Requests scan and exact Sonar Python 5.31.0.36502
// check independently establish this message. These small sources pin native
// annotation boundaries; they do not claim new reference detection coverage.
const MESSAGE: &str = "Use a more specific type than `Any` for this type hint.";

struct Case {
    name: &'static str,
    source: &'static str,
    ranges: &'static [(u32, u32, u32)],
}

const CASES: [Case; 3] = [
    Case {
        name: "parameter_return",
        source: "from typing import Any\ndef handler(value: Any) -> Any:\n    return value\n",
        ranges: &[(2, 19, 22), (2, 27, 30)],
    },
    Case {
        name: "assignment",
        source: "from typing import Any\nvalue: Any = 1\n",
        ranges: &[(2, 7, 10)],
    },
    Case {
        // This is an existing native extra, not a reference-positive fixture.
        name: "unimported_native_extra",
        source: "def parse(payload: Any) -> int:\n    return 1\n",
        ranges: &[(1, 19, 22)],
    },
];

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-s6542-message-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("fixture directory");
        Self(path)
    }

    fn analyze(
        &self,
        name: &str,
        source: &str,
        profile: Option<&str>,
        format: &str,
        exit: i32,
    ) -> Value {
        let filename = format!("{name}.py");
        let path = self.0.join(&filename);
        std::fs::write(&path, source).expect("fixture source");
        let mut command = Command::new(env!("CARGO_BIN_EXE_hoonarqube"));
        command
            .current_dir(&self.0)
            .args(["analyze", &filename, "--format", format]);
        if let Some(profile) = profile {
            command.args(["--profile", profile]);
        }
        let output = command.output().expect("run hoonarqube");
        assert_eq!(
            output.status.code(),
            Some(exit),
            "{name}/{profile:?}/{format}: {output:?}"
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
        .filter(|issue| issue["rule_key"] == "python:S6542")
        .cloned()
        .collect()
}

fn generic_targets(report: &Value, name: &str) -> Vec<Value> {
    report["issues"]
        .as_array()
        .expect("Generic issues")
        .iter()
        .filter(|issue| issue["ruleId"] == "python:S6542")
        .map(|issue| {
            assert_eq!(issue["primaryLocation"]["filePath"], format!("{name}.py"));
            issue.clone()
        })
        .collect()
}

#[test]
fn python_s6542_native_messages_and_full_ranges_match_reference() {
    let fixture = Fixture::new();
    for case in CASES {
        for profile in ["recommended", "extended", "strict"] {
            let report = fixture.analyze(case.name, case.source, Some(profile), "json", 0);
            let expected: Vec<Value> = case
                .ranges
                .iter()
                .map(|&(line, start, end)| {
                    json!({
                        "rule_key": "python:S6542", "message": MESSAGE,
                        "range": {
                            "start": { "line": line, "column": start },
                            "end": { "line": line, "column": end }
                        }
                    })
                })
                .collect();
            assert_eq!(native_targets(&report, case.name), expected, "{profile}");
        }
    }
}

#[test]
fn python_s6542_generic_messages_and_full_ranges_match_reference() {
    let fixture = Fixture::new();
    for case in CASES {
        for profile in ["recommended", "extended", "strict"] {
            let report = fixture.analyze(case.name, case.source, Some(profile), "sonar", 0);
            let expected: Vec<Value> = case
                .ranges
                .iter()
                .map(|&(line, start, end)| {
                    json!({
                        "ruleId": "python:S6542",
                        "primaryLocation": {
                            "filePath": format!("{}.py", case.name), "message": MESSAGE,
                            "textRange": {
                                "startLine": line, "startColumn": start,
                                "endLine": line, "endColumn": end
                            }
                        }
                    })
                })
                .collect();
            assert_eq!(generic_targets(&report, case.name), expected, "{profile}");
        }
    }
}

#[test]
fn python_s6542_generic_rule_definition_is_preserved() {
    let fixture = Fixture::new();
    let report = fixture.analyze("assignment", CASES[1].source, Some("strict"), "sonar", 0);
    let rules: Vec<&Value> = report["rules"]
        .as_array()
        .expect("rule definitions")
        .iter()
        .filter(|rule| rule["id"] == "python:S6542")
        .collect();
    assert_eq!(
        rules,
        vec![&json!({
            "cleanCodeAttribute": "CLEAR",
            "description": "Hoonarqube finding for `python:S6542`.",
            "engineId": "hoonarqube", "id": "python:S6542",
            "impacts": [{ "severity": "MEDIUM", "softwareQuality": "MAINTAINABILITY" }],
            "name": "python:S6542", "severity": "MAJOR", "type": "CODE_SMELL"
        })]
    );
}

#[test]
fn python_s6542_default_and_sonar_parity_profiles_stay_inactive() {
    let fixture = Fixture::new();
    for case in CASES {
        for profile in [None, Some("sonar-parity")] {
            let native = fixture.analyze(case.name, case.source, profile, "json", 0);
            let generic = fixture.analyze(case.name, case.source, profile, "sonar", 0);
            assert!(native_targets(&native, case.name).is_empty());
            assert!(generic_targets(&generic, case.name).is_empty());
        }
    }
}

#[test]
fn python_s6542_clean_controls_remain_target_free() {
    let fixture = Fixture::new();
    for (name, source) in [
        (
            "specific",
            "def parse(payload: bytes) -> int:\n    return 1\n",
        ),
        (
            "nested",
            "from typing import Any\ndef handler(value: list[Any]) -> dict[str, Any]:\n    return {}\n",
        ),
        (
            "variadic",
            "from typing import Any\ndef handler(*args: Any, **kwargs: Any) -> int:\n    return 1\n",
        ),
        (
            "attribute_alias",
            "import typing as t\ndef handler(value: t.Any) -> t.Any:\n    return value\n",
        ),
        ("string", "text = \"Any\"\n"),
    ] {
        for profile in ["strict", "sonar-parity"] {
            let native = fixture.analyze(name, source, Some(profile), "json", 0);
            let generic = fixture.analyze(name, source, Some(profile), "sonar", 0);
            assert!(native_targets(&native, name).is_empty(), "{name}/{profile}");
            assert!(
                generic_targets(&generic, name).is_empty(),
                "{name}/{profile}"
            );
        }
    }
}

#[test]
fn python_s6542_malformed_input_retains_refusal_and_diagnostics() {
    let fixture = Fixture::new();
    for profile in ["strict", "sonar-parity"] {
        let native = fixture.analyze("broken", "def f(:\n    pass\n", Some(profile), "json", 2);
        let generic = fixture.analyze("broken", "def f(:\n    pass\n", Some(profile), "sonar", 2);
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
