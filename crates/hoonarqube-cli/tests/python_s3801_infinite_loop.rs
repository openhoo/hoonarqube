use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::{Value, json};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("hoonarqube-s3801-loop-{}-{id}", std::process::id()));
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
        assert_eq!(output.stderr.is_empty(), exit == 0, "{output:?}");
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
        .filter(|issue| issue[key] == "python:S3801")
        .cloned()
        .collect()
}

fn assert_count(report: &Value, format: &str, count: usize, line: u32, column: u32) {
    let expected = if format == "json" {
        json!({"rule_key":"python:S3801","message":"Refactor this function to use \"return\" consistently.","range":{"start":{"line":line,"column":column},"end":{"line":line,"column":column+6}}})
    } else {
        json!({"ruleId":"python:S3801","primaryLocation":{"filePath":"case.py","message":"Refactor this function to use \"return\" consistently.","textRange":{"startLine":line,"startColumn":column,"endLine":line,"endColumn":column+6}}})
    };
    assert_eq!(targets(report, format), vec![expected; count]);
    if format == "sonar" {
        let definitions: Vec<_> = report["rules"]
            .as_array()
            .expect("rules")
            .iter()
            .filter(|rule| rule["id"] == "python:S3801")
            .cloned()
            .collect();
        let descriptor = json!({"id":"python:S3801","name":"python:S3801","description":"Hoonarqube finding for `python:S3801`.","engineId":"hoonarqube","cleanCodeAttribute":"CLEAR","type":"CODE_SMELL","severity":"MAJOR","impacts":[{"softwareQuality":"MAINTAINABILITY","severity":"MEDIUM"}]});
        assert_eq!(definitions, vec![descriptor; count]);
    }
}

fn assert_clean_tails(format: &str) {
    // Native reductions qualified by the retained real OSS/installed-bytecode
    // evidence; these inputs are not newly SonarQube-scanned fixtures.
    let fixture = Fixture::new();
    for source in [
        "def choose(flag):\n    while True:\n        if flag:\n            return 1\n",
        "class Engine:\n    def choose(self, flag):\n        while True:\n            if flag:\n                return 1\n",
        "async def poll(ready):\n    while True:\n        if ready:\n            return 9\n",
        "def choose(items, ready):\n    while True:\n        for item in items:\n            if item:\n                break\n        if ready:\n            return 1\n",
        "def choose(flag):\n    while True:\n        def helper(items):\n            for item in items:\n                break\n        if flag:\n            return 1\n",
        "def choose(flag):\n    while True:\n        if flag:\n            return 1\n        return None\n",
        "def spin():\n    while True:\n        pass\n",
        "def choose(flag):\n    if flag:\n        return 1\n    return 2\n",
    ] {
        for profile in ["strict", "sonar-parity"] {
            let report = fixture.analyze(source, profile, format, 0).0;
            assert_count(&report, format, 0, 1, 4);
        }
    }
}

#[test]
fn python_s3801_native_literal_true_and_scoped_breaks_are_clean() {
    assert_clean_tails("json");
}

#[test]
fn python_s3801_generic_literal_true_removes_unused_descriptor() {
    assert_clean_tails("sonar");
}

#[test]
fn python_s3801_outer_breaks_and_finite_loops_preserve_exact_findings() {
    let fixture = Fixture::new();
    for source in [
        "def choose(flag):\n    while flag:\n        if ready:\n            return 1\n",
        "def choose(flag):\n    while False:\n        if flag:\n            return 1\n",
        "def choose(items):\n    for item in items:\n        if item:\n            return 1\n",
        "def choose(flag):\n    while True:\n        if flag:\n            return 1\n        break\n",
        "def choose(stop, ready):\n    while True:\n        if stop:\n            break\n        if ready:\n            return 1\n",
        "def choose(stop, ready, lock):\n    while True:\n        with lock:\n            if stop:\n                break\n        if ready:\n            return 1\n",
        "def choose(flag):\n    while True:\n        if flag:\n            return 1\n        return\n",
        "def choose(flag):\n    if flag:\n        return 1\n    return\n",
        "def choose(items):\n    while True:\n        for item in items:\n            break\n        else:\n            break\n        return 1\n",
        "def choose(inner):\n    while True:\n        while inner:\n            break\n        else:\n            break\n        return 1\n",
    ] {
        for profile in ["strict", "sonar-parity"] {
            for format in ["json", "sonar"] {
                let report = fixture.analyze(source, profile, format, 0).0;
                assert_count(&report, format, 1, 1, 4);
            }
        }
    }
}

#[test]
fn python_s3801_existing_clean_and_bailout_controls_stay_clean() {
    let fixture = Fixture::new();
    for source in [
        "def choose(flag):\n    try:\n        if flag:\n            return 1\n    except OSError:\n        pass\n",
        "def choose(flag):\n    yield 1\n    if flag:\n        return 1\n",
        "def choose(flag):\n    if flag:\n        return 1\n    return None\n",
    ] {
        for profile in ["strict", "sonar-parity"] {
            for format in ["json", "sonar"] {
                assert_count(
                    &fixture.analyze(source, profile, format, 0).0,
                    format,
                    0,
                    1,
                    4,
                );
            }
        }
    }
}

#[test]
fn python_s3801_infinite_loop_does_not_offer_source_edits() {
    let source = "def choose(flag):\n    while True:\n        if flag:\n            return 1\n";
    let fixture = Fixture::new();
    for profile in ["strict", "sonar-parity"] {
        let before = fixture.analyze(source, profile, "json", 0);
        assert_count(&before.0, "json", 0, 1, 4);
        for mode in ["--diff", "--apply"] {
            let output = fixture.run(&[
                "fix",
                "--profile",
                profile,
                "--rule",
                "python:S3801",
                mode,
                "--json",
                "case.py",
            ]);
            assert_eq!(output.status.code(), Some(0), "{output:?}");
            assert!(output.stderr.is_empty());
            let report: Value = serde_json::from_slice(&output.stdout).expect("fix report");
            assert_eq!(report["applied"], 0);
            assert_eq!(report["mechanical"], 0);
            assert_eq!(report["files"], json!([]));
            assert_eq!(report["warnings"], json!([]));
            assert_eq!(
                std::fs::read(fixture.0.join("case.py")).expect("source"),
                source.as_bytes()
            );
            let after = fixture.analyze(source, profile, "json", 0);
            assert_eq!(after.1.stdout, before.1.stdout);
            assert_eq!(after.1.stderr, before.1.stderr);
        }
    }
}

#[test]
fn python_s3801_malformed_loop_stays_incomplete() {
    let fixture = Fixture::new();
    for source in [
        "value =\n",
        "def choose():\n    while True\n        return 1\n",
    ] {
        for profile in ["strict", "sonar-parity"] {
            for format in ["json", "sonar"] {
                let (report, output) = fixture.analyze(source, profile, format, 2);
                assert!(!output.stderr.is_empty());
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
                } else {
                    assert!(
                        report["issues"]
                            .as_array()
                            .expect("issues")
                            .iter()
                            .any(|issue| issue["ruleId"] == "python:ParsingError")
                    );
                }
            }
        }
    }
}
