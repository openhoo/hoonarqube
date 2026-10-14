use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::{Value, json};

// Sonar Python 5.31.0.36502 independently reports the raw positive at
// 3:14–3:18. Other ranges below preserve existing native behavior.
const MESSAGE: &str =
    "Consider replacing this octal escape sequence with a Unicode or hexadecimal sequence instead.";
const POSITIVE: &str = "import re\n\nre.compile(r'a\\101b')\n";
const PROFILES: [Option<&str>; 5] = [
    None,
    Some("recommended"),
    Some("extended"),
    Some("strict"),
    Some("sonar-parity"),
];

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-s6537-message-{}-{id}",
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
        .filter(|issue| issue[key] == "python:S6537")
        .cloned()
        .collect()
}

fn expected_issue(format: &str, start: u32, end: u32) -> Value {
    if format == "json" {
        json!({
            "rule_key": "python:S6537", "message": MESSAGE,
            "range": {
                "start": { "line": 3, "column": start },
                "end": { "line": 3, "column": end }
            }
        })
    } else {
        json!({
            "ruleId": "python:S6537",
            "primaryLocation": {
                "filePath": "case.py", "message": MESSAGE,
                "textRange": {
                    "startLine": 3, "startColumn": start,
                    "endLine": 3, "endColumn": end
                }
            }
        })
    }
}

#[test]
fn python_s6537_raw_and_string_messages_preserve_full_issue_values() {
    let fixture = Fixture::new();
    for (source, ranges) in [
        (POSITIVE, vec![(14, 18)]),
        ("import re\n\nre.compile('a\\101b')\n", vec![(13, 14)]),
        (
            "import re\n\nre.compile(r'a\\101b\\033c')\n",
            vec![(14, 18), (19, 23)],
        ),
        ("import re\n\nre.compile(r'a\\0b')\n", vec![(14, 16)]),
    ] {
        for profile in PROFILES {
            for format in ["json", "sonar"] {
                let report = fixture.analyze(source, profile, format, 0);
                let expected: Vec<Value> = ranges
                    .iter()
                    .map(|&(start, end)| expected_issue(format, start, end))
                    .collect();
                assert_eq!(targets(&report, format), expected, "{profile:?}/{format}");
            }
        }
    }
}

#[test]
fn python_s6537_hex_unicode_and_valid_backreference_stay_clean() {
    let fixture = Fixture::new();
    for source in [
        "import re\n\nre.compile(r'a\\x41b')\n",
        "import re\n\nre.compile(r'a\\u0041b')\n",
        "import re\n\nre.compile(r'(a)\\1')\n",
    ] {
        for profile in PROFILES {
            for format in ["json", "sonar"] {
                let report = fixture.analyze(source, profile, format, 0);
                assert!(targets(&report, format).is_empty());
            }
        }
    }
}

#[test]
fn python_s6537_malformed_input_preserves_failed_inventory_and_diagnostics() {
    let fixture = Fixture::new();
    for profile in PROFILES {
        let native = fixture.analyze("def f(:\n    pass\n", profile, "json", 2);
        let generic = fixture.analyze("def f(:\n    pass\n", profile, "sonar", 2);
        assert!(targets(&native, "json").is_empty());
        assert!(targets(&generic, "sonar").is_empty());
        assert_eq!(
            native["project"]["files"][0]["reason"],
            "syntax tree contains recovered or missing nodes"
        );
        assert!(
            native["files"][0]["issues"]
                .as_array()
                .expect("recovered diagnostics")
                .iter()
                .any(|issue| issue["rule_key"] == "python:ParsingError")
        );
        assert!(
            generic["issues"]
                .as_array()
                .expect("Generic diagnostics")
                .iter()
                .any(|issue| issue["ruleId"] == "python:ParsingError")
        );
    }
}

#[test]
fn python_s6537_unavailable_diff_and_apply_preserve_source_and_diagnostics() {
    let fixture = Fixture::new();
    let before = fixture.analyze(POSITIVE, Some("strict"), "json", 0);
    for mode in ["--diff", "--apply"] {
        let output = fixture.run(&[
            "fix",
            "--profile",
            "strict",
            "--rule",
            "python:S6537",
            "--suggestion",
            "python:S6537=s6537-replace-octal",
            mode,
            "--json",
            "case.py",
        ]);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let report: Value = serde_json::from_slice(&output.stdout).expect("fix report");
        assert_eq!(report["applied"], 0);
        assert_eq!(report["mechanical"], 0);
        assert_eq!(report["files"], json!([]));
        assert_eq!(
            report["warnings"],
            json!(["selected suggestion python:S6537=s6537-replace-octal is unavailable"])
        );
        assert_eq!(
            std::fs::read_to_string(fixture.0.join("case.py")).expect("refusal readback"),
            POSITIVE
        );
        assert_eq!(fixture.analyze(POSITIVE, Some("strict"), "json", 0), before);
    }
}
