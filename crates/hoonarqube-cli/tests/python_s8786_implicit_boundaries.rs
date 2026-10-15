use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::{Value, json};

const KEY: &str = "python:S8786";
const MESSAGE: &str = "Simplify this regular expression to reduce its runtime, as it has super-linear performance due to backtracking.";

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-s8786-boundaries-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("fixture directory");
        Self(path)
    }

    fn analyze(&self, source: &str, profile: &str, format: &str, exit: i32) -> (Value, Output) {
        std::fs::write(self.0.join("case.py"), source).expect("source");
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
        assert_eq!(output.status.code(), Some(exit), "{output:?}");
        assert_eq!(output.stderr.is_empty(), exit == 0, "{output:?}");
        assert_eq!(
            std::fs::read(self.0.join("case.py")).expect("source readback"),
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
        .filter(|issue| issue[key] == KEY)
        .cloned()
        .collect()
}

fn assert_targets(report: &Value, format: &str, source: &str, patterns: &[&str]) {
    let expected: Vec<_> = patterns
        .iter()
        .map(|pattern| {
            let opener = format!("r\"{pattern}\"");
            let start = source.find(&opener).expect("literal pattern") + 2;
            let position = |offset: usize| {
                let prefix = &source[..offset];
                let last = prefix.rsplit('\n').next().unwrap();
                let column = if format == "sonar" {
                    last.encode_utf16().count()
                } else {
                    last.chars().count()
                };
                (
                    prefix.bytes().filter(|&byte| byte == b'\n').count() + 1,
                    column,
                )
            };
            let (line, column) = position(start);
            let (end_line, end_column) = position(start + pattern.len());
            if format == "json" {
                json!({"rule_key":KEY,"message":MESSAGE,"range":{"start":{"line":line,"column":column},"end":{"line":end_line,"column":end_column}}})
            } else {
                json!({"ruleId":KEY,"primaryLocation":{"filePath":"case.py","message":MESSAGE,"textRange":{"startLine":line,"startColumn":column,"endLine":end_line,"endColumn":end_column}}})
            }
        })
        .collect();
    assert_eq!(targets(report, format), expected, "{source}");
    if format == "sonar" {
        let definitions: Vec<_> = report["rules"]
            .as_array()
            .expect("rules")
            .iter()
            .filter(|rule| rule["id"] == KEY)
            .cloned()
            .collect();
        let descriptor = json!({"cleanCodeAttribute":"EFFICIENT","description":"Hoonarqube finding for `python:S8786`.","engineId":"hoonarqube","id":KEY,"impacts":[{"severity":"MEDIUM","softwareQuality":"RELIABILITY"}],"name":KEY,"severity":"MAJOR","type":"CODE_SMELL"});
        assert_eq!(
            definitions,
            if patterns.is_empty() {
                vec![]
            } else {
                vec![descriptor]
            }
        );
    }
}

fn check_source(source: &str, patterns: &[&str]) {
    let fixture = Fixture::new();
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            let report = fixture.analyze(source, profile, format, 0).0;
            assert_targets(&report, format, source, patterns);
        }
    }
}

#[test]
fn python_s8786_implicit_boundaries_remove_direct_and_grouped_findings_and_descriptor() {
    // Native reductions backed by the retained OSS/installed-bytecode evidence;
    // these are not standalone SonarQube-scanned fixtures.
    for pattern in [
        r"^(\d+)\.(\d+)\.\d+",
        r"^a+Z",
        r"\Aa+Z",
        r"\ba+Z",
        r"\Ba+Z",
        r"(^a+)Z",
        r"(?:^a+)Z",
        r"^a+Z|^b+Z",
    ] {
        check_source(
            &format!("import re\nre.search(r\"{pattern}\", text)\n"),
            &[],
        );
    }
}

#[test]
fn python_s8786_implicit_boundaries_preserve_unanchored_optional_and_internal_overlaps() {
    for pattern in [r"a+Z", r"^a+Z|b+Z", r"(?:^)?a+Z", r"^a+a+Z", r"\Aa+a+Z"] {
        check_source(
            &format!("import re\nre.search(r\"{pattern}\", text)\n"),
            &[pattern],
        );
    }
    check_source("import re\nre.search(r\"^a+b+Z\", text)\n", &[]);
    let pattern = "<meta.*?content=charset=(.+?)[>]";
    check_source(
        &format!("import re\nre.compile(r\"{pattern}\", re.I)\n"),
        &[pattern],
    );
    check_source(
        "import re\nre.compile(r\"([Ww]/)?(?:\\\"(.*?)\\\"|(.*?))(?:\\s*,\\s*|$)\")\n",
        &[],
    );
}

#[test]
fn python_s8786_implicit_boundaries_keep_usage_and_flags_contract() {
    // This pins the installed helper's heuristic. In particular, a clean
    // MULTILINE/DOTALL result does not certify runtime complexity.
    for expression in [
        "re.fullmatch(r\"a+Z\", text)",
        "re.match(r\"a+Z\", text)",
        "pattern = re.compile(r\"^a+Z\")\npattern.search(text)",
        "pattern = re.compile(r\"^a+Z\")\npattern.fullmatch(text)",
        "pattern = re.compile(r\"^a+Z\")\npattern.search(text)\npattern.fullmatch(text)",
        "re.search(r\"^a+Z\", text, re.MULTILINE)",
        "re.search(r\"^.*Z\", text, re.MULTILINE | re.DOTALL)",
        "re.search(r\"(?m)^a+Z\", text)",
        "re.search(r\"(?m:^a+)Z\", text)",
    ] {
        check_source(&format!("import re\n{expression}\n"), &[]);
    }
}

#[test]
fn python_s8786_implicit_boundaries_unicode_crlf_preserves_exact_positive_range() {
    let source =
        "import re\r\nmarker = \"😀\"; re.search(r\"^a+Z\", text); re.search(r\"a+Z\", text)\r\n";
    check_source(source, &["a+Z"]);
}

#[test]
fn python_s8786_implicit_boundaries_cached_reanalysis_observes_anchor_changes() {
    let anchored = "import re\nre.search(r\"^a+Z\", text)\n";
    let unanchored = "import re\nre.search(r\"a+Z\", text)\n";
    let fixture = Fixture::new();
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            let initial = fixture.analyze(anchored, profile, format, 0);
            assert_targets(&initial.0, format, anchored, &[]);
            let changed = fixture.analyze(unanchored, profile, format, 0);
            assert_targets(&changed.0, format, unanchored, &["a+Z"]);
            let restored = fixture.analyze(anchored, profile, format, 0);
            assert_eq!(initial.1.stdout, restored.1.stdout);
            assert_eq!(initial.1.stderr, restored.1.stderr);
        }
    }
}

#[test]
fn python_s8786_implicit_boundaries_malformed_inputs_remain_incomplete() {
    let fixture = Fixture::new();
    for source in [
        "import re\nre.search(r\"^a+Z\", text\n",
        "import re\ndef broken(:\n    pass\n",
    ] {
        for profile in ["strict", "sonar-parity"] {
            for format in ["json", "sonar"] {
                let report = fixture.analyze(source, profile, format, 2).0;
                assert_targets(&report, format, source, &[]);
                let (issues, key) = if format == "json" {
                    (&report["files"][0]["issues"], "rule_key")
                } else {
                    (&report["issues"], "ruleId")
                };
                assert!(
                    issues
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|issue| issue[key] == "python:ParsingError")
                );
            }
        }
    }
}
