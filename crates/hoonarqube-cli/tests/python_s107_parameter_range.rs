use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::{Value, json};

const PROFILES: [&str; 2] = ["strict", "sonar-parity"];
struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("hoonarqube-s107-range-{}-{id}", std::process::id()));
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

    fn analyze(&self, source: &str, profile: Option<&str>, format: &str, exit: i32) -> Value {
        let path = self.0.join("case.py");
        std::fs::write(&path, source).expect("fixture source");
        let mut args = vec!["analyze", "case.py", "--format", format];
        if let Some(profile) = profile {
            args.extend(["--profile", profile]);
        }
        let output = self.run(&args);
        assert_eq!(output.status.code(), Some(exit), "{output:?}");
        assert_eq!(std::fs::read_to_string(path).expect("readback"), source);
        let report: Value = serde_json::from_slice(&output.stdout).expect("report JSON");
        if format == "json" {
            assert_eq!(report["project"]["complete"], exit == 0);
            assert_eq!(report["project"]["files"][0]["path"], "case.py");
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

fn targets(report: &Value, format: &str) -> Vec<Value> {
    let (issues, key) = if format == "json" {
        assert_eq!(report["files"][0]["path"], "case.py");
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

fn expected_issue(format: &str, start: (u32, u32), end: (u32, u32)) -> Value {
    let message = "Function \"wide\" has 14 parameters, which is greater than the 13 authorized.";
    if format == "json" {
        json!({"rule_key": "python:S107", "message": message,
            "range": {"start": {"line": start.0, "column": start.1},
                      "end": {"line": end.0, "column": end.1}}})
    } else {
        json!({"ruleId": "python:S107", "primaryLocation": {"filePath": "case.py", "message": message,
            "textRange": {"startLine": start.0, "startColumn": start.1,
                          "endLine": end.0, "endColumn": end.1}}})
    }
}

fn assert_leading_marker(format: &str) {
    let fixture = Fixture::new();
    // The real Click witness starts at its bare marker (404:4), not its
    // first keyword-only name (405:4). These reductions retain that tree shape.
    for (source, start, end) in [
        (
            "def wide(*, a, b, c, d, e, f, g, h, i, j, k, l, m, n):\n    pass\n",
            (1, 9),
            (1, 52),
        ),
        (
            "def wide(\n    *,\n    a: int = 1,\n    b: int = 2,\n    c: int = 3,\n    d: int = 4,\n    e: int = 5,\n    f: int = 6,\n    g: int = 7,\n    h: int = 8,\n    i: int = 9,\n    j: int = 10,\n    k: int = 11,\n    l: int = 12,\n    m: int = 13,\n    n: int = 14,\n):\n    pass\n",
            (2, 4),
            (16, 16),
        ),
        (
            "@decorator\nasync def wide(\n    *,\n    a: int = 1,\n    b: int = 2,\n    c: int = 3,\n    d: int = 4,\n    e: int = 5,\n    f: int = 6,\n    g: int = 7,\n    h: int = 8,\n    i: int = 9,\n    j: int = 10,\n    k: int = 11,\n    l: int = 12,\n    m: int = 13,\n    n: int = 14,\n):\n    pass\n",
            (3, 4),
            (17, 16),
        ),
        (
            "def wide(\n    # * comment\n    *, # marker\n    a: str = \"*\",\n    b: str = \"*\",\n    c: str = \"*\",\n    d: str = \"*\",\n    e: str = \"*\",\n    f: str = \"*\",\n    g: str = \"*\",\n    h: str = \"*\",\n    i: str = \"*\",\n    j: str = \"*\",\n    k: str = \"*\",\n    l: str = \"*\",\n    m: str = \"*\",\n    n: str = \"*\",\n):\n    pass\n",
            (3, 4),
            (17, 17),
        ),
        (
            "def wide(\n    *,\n    a: int = 1,\n    b: int = 2,\n    c: int = 3,\n    d: int = 4,\n    e: int = 5,\n    f: int = 6,\n    g: int = 7,\n    h: int = 8,\n    i: int = 9,\n    j: int = 10,\n    k: int = 11,\n    l: int = 12,\n    m: int = 13,\n    n: int = 14\n):\n    pass\n",
            (2, 4),
            (16, 15),
        ),
    ] {
        for profile in PROFILES {
            let report = fixture.analyze(source, Some(profile), format, 0);
            assert_eq!(
                targets(&report, format),
                vec![expected_issue(format, start, end)],
                "{profile}/{format}"
            );
        }
    }
}

#[test]
fn python_s107_native_starts_at_leading_bare_marker() {
    assert_leading_marker("json");
}

#[test]
fn python_s107_generic_starts_at_leading_bare_marker() {
    assert_leading_marker("sonar");
}

#[test]
fn python_s107_threshold_and_empty_controls_stay_clean() {
    let fixture = Fixture::new();
    for source in [
        "def f():\n    pass\n",
        "def f(*, a):\n    pass\n",
        "def f(*, a, b, c, d, e, f, g, h, i, j, k, l, m):\n    pass\n",
        "def f(a, b, c, d, e, f, g, h, i, j, k, l, m):\n    pass\n",
    ] {
        for profile in PROFILES {
            for format in ["json", "sonar"] {
                assert!(
                    targets(&fixture.analyze(source, Some(profile), format, 0), format).is_empty()
                );
            }
        }
    }
}

#[test]
fn python_s107_generic_rule_definition_is_preserved() {
    let fixture = Fixture::new();
    let report = fixture.analyze(
        "def f(*, a, b, c, d, e, f, g, h, i, j, k, l, m, n):\n    pass\n",
        Some("strict"),
        "sonar",
        0,
    );
    let rules: Vec<_> = report["rules"]
        .as_array()
        .expect("rules")
        .iter()
        .filter(|r| r["id"] == "python:S107")
        .cloned()
        .collect();
    assert_eq!(
        rules,
        vec![
            json!({"id":"python:S107","name":"python:S107","description":"Hoonarqube finding for `python:S107`.","engineId":"hoonarqube","cleanCodeAttribute":"FOCUSED","type":"CODE_SMELL","severity":"MAJOR","impacts":[{"softwareQuality":"MAINTAINABILITY","severity":"MEDIUM"}]})
        ]
    );
}

#[test]
fn python_s107_malformed_input_preserves_refusal_and_diagnostics() {
    let fixture = Fixture::new();
    for profile in PROFILES {
        for format in ["json", "sonar"] {
            let report = fixture.analyze(
                "def broken(\n    *,\n    value=\n",
                Some(profile),
                format,
                2,
            );
            let (issues, key) = if format == "json" {
                (&report["files"][0]["issues"], "rule_key")
            } else {
                (&report["issues"], "ruleId")
            };
            assert!(
                issues
                    .as_array()
                    .expect("diagnostics")
                    .iter()
                    .any(|i| i[key] == "python:ParsingError")
            );
            if format == "json" {
                assert_eq!(
                    report["project"]["files"][0]["reason"],
                    "syntax tree contains recovered or missing nodes"
                );
            }
        }
    }
}

#[test]
fn python_s107_no_fix_or_suggestion_preserves_source_and_reanalysis() {
    let fixture = Fixture::new();
    let source = "def wide(*, a, b, c, d, e, f, g, h, i, j, k, l, m, n):\n    pass\n";
    let before = fixture.analyze(source, Some("strict"), "json", 0);
    for mode in ["--diff", "--apply"] {
        for unavailable in [false, true] {
            let mut args = vec![
                "fix",
                "--profile",
                "strict",
                "--rule",
                "python:S107",
                mode,
                "--json",
            ];
            if unavailable {
                args.extend(["--suggestion", "python:S107=s107-reduce-parameters"]);
            }
            args.push("case.py");
            let output = fixture.run(&args);
            assert_eq!(
                output.status.code(),
                Some(i32::from(unavailable)),
                "{output:?}"
            );
            let report: Value = serde_json::from_slice(&output.stdout).expect("fix report");
            assert_eq!(report["applied"], 0);
            assert_eq!(report["mechanical"], 0);
            assert_eq!(report["files"], json!([]));
            assert_eq!(
                report["warnings"],
                if unavailable {
                    json!(["selected suggestion python:S107=s107-reduce-parameters is unavailable"])
                } else {
                    json!([])
                }
            );
            assert_eq!(
                std::fs::read_to_string(fixture.0.join("case.py")).expect("readback"),
                source
            );
            assert_eq!(fixture.analyze(source, Some("strict"), "json", 0), before);
        }
    }
}
