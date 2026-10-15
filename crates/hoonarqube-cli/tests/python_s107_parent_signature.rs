use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::{Value, json};

const CONSTRUCTORS: &str = "class Base:\n    def __init__(self, a, b, c, d, e, f, g, h, i, j, k, l, m, n):\n        pass\nclass Child(Base):\n    def __init__(self, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r):\n        pass\nclass Unrelated:\n    def __init__(self, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o):\n        pass\n";

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-s107-parent-{}-{id}",
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

    fn analyze(&self, source: &str, profile: &str, format: &str, exit: i32) -> (Value, Output) {
        std::fs::write(self.0.join("case.py"), source).expect("source");
        let output = self.run(&[
            "analyze",
            "case.py",
            "--profile",
            profile,
            "--format",
            format,
        ]);
        assert_eq!(output.status.code(), Some(exit), "{output:?}");
        if exit == 0 {
            assert!(output.stderr.is_empty(), "{output:?}");
        }
        assert_eq!(
            std::fs::read(self.0.join("case.py")).expect("readback"),
            source.as_bytes()
        );
        let report: Value = serde_json::from_slice(&output.stdout).expect("report");
        if format == "json" {
            assert_eq!(report["project"]["complete"], exit == 0);
            assert_eq!(report["project"]["metrics"]["files"], u32::from(exit == 0));
            assert_eq!(report["project"]["files"][0]["path"], "case.py");
            assert_eq!(
                report["project"]["files"][0]["status"],
                if exit == 0 { "complete" } else { "failed" }
            );
            if exit == 0 {
                assert_eq!(report["project"]["warnings"], json!([]));
                assert_eq!(report["project"]["files"][0]["reason"], Value::Null);
            }
        }
        assert_eq!(report.get("parity").is_some(), profile == "sonar-parity");
        if profile == "sonar-parity" {
            assert_eq!(
                report["parity"]["completeness"],
                if exit == 0 {
                    "complete_native_analysis"
                } else {
                    "incomplete"
                }
            );
        }
        (report, output)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn targets(report: &Value, format: &str) -> Vec<Value> {
    let (issues, key) = if format == "json" {
        (&report["files"][0]["issues"], "rule_key")
    } else {
        (&report["issues"], "ruleId")
    };
    issues
        .as_array()
        .expect("issues")
        .iter()
        .filter(|issue| issue[key] == "python:S107")
        .cloned()
        .collect()
}

fn expected(format: &str, name: &str, count: u32, line: u32, col: u32, end: u32) -> Value {
    let message = format!(
        "Method \"{name}\" has {count} parameters, which is greater than the 13 authorized."
    );
    if format == "json" {
        json!({"rule_key":"python:S107","message":message,
            "range":{"start":{"line":line,"column":col},"end":{"line":line,"column":end}}})
    } else {
        json!({"ruleId":"python:S107","primaryLocation":{"filePath":"case.py",
            "message":message,"textRange":{"startLine":line,"endLine":line,
            "startColumn":col,"endColumn":end}}})
    }
}

fn assert_constructors(format: &str) {
    // Native acceptance reductions of the installed parent-signature check;
    // these synthetic controls are not newly reference-scanned fixtures.
    let fixture = Fixture::new();
    for profile in ["strict", "sonar-parity"] {
        let report = fixture.analyze(CONSTRUCTORS, profile, format, 0).0;
        assert_eq!(
            targets(&report, format),
            vec![
                expected(format, "__init__", 14, 2, 17, 63),
                expected(format, "__init__", 15, 8, 17, 66),
            ],
            "{profile}/{format}"
        );
        if format == "sonar" {
            let definitions: Vec<_> = report["rules"]
                .as_array()
                .expect("rules")
                .iter()
                .filter(|rule| rule["id"] == "python:S107")
                .cloned()
                .collect();
            assert_eq!(
                definitions,
                vec![
                    json!({"id":"python:S107","name":"python:S107","description":"Hoonarqube finding for `python:S107`.","engineId":"hoonarqube","cleanCodeAttribute":"FOCUSED","type":"CODE_SMELL","severity":"MAJOR","impacts":[{"softwareQuality":"MAINTAINABILITY","severity":"MEDIUM"}]})
                ]
            );
        }
    }
}

#[test]
fn python_s107_native_parent_signature_retains_parent_and_unrelated_constructor() {
    assert_constructors("json");
}

#[test]
fn python_s107_generic_parent_signature_retains_parent_and_unrelated_constructor() {
    assert_constructors("sonar");
}

#[test]
fn python_s107_parent_raw_threshold_preserves_ordinary_method_boundary() {
    let source = "class At:\n    def change(self, a, b, c, d, e, f, g, h, i, j, k, l):\n        pass\nclass Report(At):\n    def change(self, a, b, c, d, e, f, g, h, i, j, k, l, m, n):\n        pass\nclass Above:\n    def change(self, a, b, c, d, e, f, g, h, i, j, k, l, m):\n        pass\nclass Suppressed(Above):\n    def change(self, a, b, c, d, e, f, g, h, i, j, k, l, m, n):\n        pass\n";
    let fixture = Fixture::new();
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            let report = fixture.analyze(source, profile, format, 0).0;
            assert_eq!(
                targets(&report, format),
                vec![expected(format, "change", 14, 5, 15, 61)],
                "{profile}/{format}"
            );
        }
    }
}

#[test]
fn python_s107_first_parent_and_uncertain_bindings_keep_findings() {
    let parent =
        "class Wide:\n    def change(self, a, b, c, d, e, f, g, h, i, j, k, l, m):\n        pass\n";
    let child = "    def change(self, a, b, c, d, e, f, g, h, i, j, k, l, m, n):\n        pass\n";
    let fixture = Fixture::new();
    for declaration in [
        "class Narrow:\n    def change(self):\n        pass\nclass Child(Narrow, Wide):\n",
        "class Child(Unknown, Wide):\n",
        "Wide = replacement\nclass Child(Wide):\n",
        "Wide.change = replacement\nclass Child(Wide):\n",
    ] {
        let source = format!("{parent}{declaration}{child}");
        let line = u32::try_from(source.lines().count() - 1).expect("line");
        for profile in ["strict", "sonar-parity"] {
            for format in ["json", "sonar"] {
                let report = fixture.analyze(&source, profile, format, 0).0;
                assert_eq!(
                    targets(&report, format),
                    vec![expected(format, "change", 14, line, 15, 61)],
                    "{profile}/{format}: {source}"
                );
            }
        }
    }
}

#[test]
fn python_s107_unresolved_inheritance_and_clean_child_stay_distinct() {
    let fixture = Fixture::new();
    let bad = "from external import Base\nclass Child(Base):\n    def change(self, a, b, c, d, e, f, g, h, i, j, k, l, m, n):\n        pass\n";
    let good = "class Base:\n    def change(self):\n        pass\nclass Child(Base):\n    def change(self, a, b, c, d, e, f, g, h, i, j, k, l, m):\n        pass\n";
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            assert_eq!(
                targets(&fixture.analyze(bad, profile, format, 0).0, format),
                vec![expected(format, "change", 14, 3, 15, 61)]
            );
            assert!(targets(&fixture.analyze(good, profile, format, 0).0, format).is_empty());
        }
    }
}

#[test]
fn python_s107_parent_signature_does_not_offer_source_edits() {
    let fixture = Fixture::new();
    for profile in ["strict", "sonar-parity"] {
        let before = fixture.analyze(CONSTRUCTORS, profile, "json", 0);
        for mode in ["--diff", "--apply"] {
            let output = fixture.run(&[
                "fix",
                "--profile",
                profile,
                "--rule",
                "python:S107",
                mode,
                "--json",
                "case.py",
            ]);
            assert_eq!(output.status.code(), Some(0), "{output:?}");
            assert!(output.stderr.is_empty(), "{output:?}");
            let report: Value = serde_json::from_slice(&output.stdout).expect("fix report");
            assert_eq!(report["applied"], 0);
            assert_eq!(report["mechanical"], 0);
            assert_eq!(report["files"], json!([]));
            assert_eq!(report["warnings"], json!([]));
            assert_eq!(
                std::fs::read(fixture.0.join("case.py")).expect("source"),
                CONSTRUCTORS.as_bytes()
            );
            let after = fixture.analyze(CONSTRUCTORS, profile, "json", 0);
            assert_eq!(after.1.stdout, before.1.stdout);
            assert_eq!(after.1.stderr, before.1.stderr);
        }
    }
}

#[test]
fn python_s107_parent_signature_malformed_analysis_remains_incomplete() {
    let fixture = Fixture::new();
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            let (report, output) = fixture.analyze("value =\n", profile, format, 2);
            assert!(!output.stderr.is_empty());
            assert!(targets(&report, format).is_empty());
            if format == "json" {
                assert_eq!(
                    report["project"]["files"][0]["reason"],
                    "syntax tree contains recovered or missing nodes"
                );
                assert!(
                    report["files"][0]["issues"]
                        .as_array()
                        .expect("issues")
                        .iter()
                        .any(|issue| issue["rule_key"] == "python:ParsingError")
                );
            }
            let repeated = fixture.analyze("value =\n", profile, format, 2).1;
            assert_eq!(repeated.stdout, output.stdout);
            assert_eq!(repeated.stderr, output.stderr);
        }
    }
}
