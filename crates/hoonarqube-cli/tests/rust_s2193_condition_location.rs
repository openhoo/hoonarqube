use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::{Command, Output};

const KEY: &str = "rust:S2193";
const MESSAGE: &str = "Avoid using floating-point numbers as loop counters.";
const FILE: &str = "src/counter.rs";
const ORIGINAL: &str = include_str!("../../../.oracle/sonar/projects/oracle-rust/src/s2193_bad.rs");

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("hoonarqube-s2193-{}-{id}", std::process::id()));
        std::fs::create_dir(&path).expect("fixture directory");
        std::fs::create_dir(path.join("src")).expect("source directory");
        Self(path)
    }

    fn write(&self, source: &[u8]) {
        std::fs::write(self.0.join(FILE), source).expect("source");
    }

    fn assert_source(&self, source: &[u8]) {
        assert_eq!(std::fs::read(self.0.join(FILE)).expect("readback"), source);
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args(args)
            .output()
            .expect("actual CLI")
    }

    fn analyze(&self, profile: &str, format: &str, exit: i32) -> Value {
        let mut args = vec!["analyze", "--format", format];
        if profile != "default" {
            args.extend(["--profile", profile]);
        }
        args.extend(["--", FILE]);
        let output = self.run(&args);
        assert_eq!(output.status.code(), Some(exit), "{output:?}");
        if exit == 0 {
            assert!(output.stderr.is_empty(), "{output:?}");
        }
        let document: Value = serde_json::from_slice(&output.stdout).expect("actual report");
        if format == "json" {
            assert_eq!(document["project"]["complete"], exit == 0);
        }
        document
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn issues<'a>(document: &'a Value, format: &str) -> Vec<&'a Value> {
    if format == "json" {
        document["files"]
            .as_array()
            .expect("native files")
            .iter()
            .flat_map(|file| file["issues"].as_array().expect("native issues"))
            .collect()
    } else {
        document["issues"]
            .as_array()
            .expect("generic issues")
            .iter()
            .collect()
    }
}

fn rule<'a>(issue: &'a Value, format: &str) -> &'a str {
    issue[if format == "json" {
        "rule_key"
    } else {
        "ruleId"
    }]
    .as_str()
    .expect("rule key")
}

fn expected(key: &str, message: &str, range: (u32, u32, u32, u32), format: &str) -> Value {
    let (sl, sc, el, ec) = range;
    if format == "json" {
        json!({"rule_key":key,"message":message,"range":{"start":{"line":sl,"column":sc},"end":{"line":el,"column":ec}}})
    } else {
        json!({"ruleId":key,"primaryLocation":{"filePath":FILE,"message":message,"textRange":{"startLine":sl,"startColumn":sc,"endLine":el,"endColumn":ec}}})
    }
}

fn expected_rule() -> Value {
    json!({
        "id":KEY,"name":KEY,"description":"Hoonarqube finding for `rust:S2193`.",
        "engineId":"hoonarqube","cleanCodeAttribute":"LOGICAL","type":"BUG","severity":"MINOR",
        "impacts":[{"softwareQuality":"RELIABILITY","severity":"LOW"}],
    })
}

#[test]
fn rust_s2193_cli_original_reference_identity_preserves_surrounding_finding() {
    let fixture = Fixture::new();
    fixture.write(ORIGINAL.as_bytes());
    for profile in [
        "default",
        "sonar-parity",
        "recommended",
        "extended",
        "strict",
    ] {
        for format in ["json", "sonar"] {
            let document = fixture.analyze(profile, format, 0);
            assert_eq!(
                issues(&document, format),
                [
                    &expected(KEY, MESSAGE, (4, 10, 4, 24), format),
                    &expected(
                        "rust:S106",
                        "Use a logging framework to log this message to the console.",
                        (5, 8, 5, 40),
                        format,
                    ),
                ]
            );
            if format == "sonar" {
                let target: Vec<_> = document["rules"]
                    .as_array()
                    .expect("rules")
                    .iter()
                    .filter(|rule| rule["id"] == KEY)
                    .collect();
                assert_eq!(target, [&expected_rule()]);
            }
        }
    }
    fixture.assert_source(ORIGINAL.as_bytes());
}

#[test]
fn rust_s2193_cli_named_multiline_and_distinct_loops_have_condition_ranges() {
    let fixture = Fixture::new();
    for (source, ranges) in [
        (
            "fn main() {\n    let mut progress = 0.0;\n    while progress < 10.0 {\n        progress += 1.0;\n    }\n}\n",
            vec![(3, 10, 3, 25)],
        ),
        (
            "fn main() {\n    let mut progress = 0.0;\n    while progress\n        < 10.0\n    {\n        progress += 1.0;\n    }\n}\n",
            vec![(3, 10, 4, 14)],
        ),
        (
            "fn main() {\n    let mut counter = 0.0;\n    while counter < 10.0 {\n        counter += 1.0;\n    }\n    let mut counter = 0.0;\n    while counter < 10.0 {\n        counter += 1.0;\n    }\n}\n",
            vec![(3, 10, 3, 24), (7, 10, 7, 24)],
        ),
        (
            "fn main() {\n    let mut counter = 0.0;\n\n\n    while counter < 10.0 { counter += 1.0; }\n}\n",
            vec![(5, 10, 5, 24)],
        ),
    ] {
        fixture.write(source.as_bytes());
        for format in ["json", "sonar"] {
            let document = fixture.analyze("sonar-parity", format, 0);
            let actual = issues(&document, format);
            let expected: Vec<_> = ranges
                .iter()
                .map(|range| expected(KEY, MESSAGE, *range, format))
                .collect();
            assert_eq!(actual, expected.iter().collect::<Vec<_>>(), "{source}");
            if format == "sonar" {
                assert_eq!(document["rules"], json!([expected_rule()]));
            }
        }
        fixture.assert_source(source.as_bytes());
    }
}

#[test]
fn rust_s2193_cli_unicode_scalar_and_generic_utf16_columns_survive_crlf() {
    let fixture = Fixture::new();
    let source = "fn main() {\n    let mut progress = 0.0;\n    let _label = \"é😀\"; while progress < 10.0 {\n        progress += 1.0;\n    }\n}\n";
    for source in [source.to_string(), source.replace('\n', "\r\n")] {
        fixture.write(source.as_bytes());
        for (format, range) in [("json", (3, 29, 3, 44)), ("sonar", (3, 30, 3, 45))] {
            let document = fixture.analyze("sonar-parity", format, 0);
            assert_eq!(
                issues(&document, format),
                [&expected(KEY, MESSAGE, range, format)]
            );
        }
        fixture.assert_source(source.as_bytes());
    }
}

#[test]
fn rust_s2193_cli_clean_controls_preserve_existing_eligibility_boundary() {
    let fixture = Fixture::new();
    for source in [
        include_str!("../../../.oracle/sonar/projects/oracle-rust/src/s2193_good.rs"),
        "fn main() { let mut counter = 0; while counter < 10 { counter += 1; } }\n",
        "fn main() { let mut counter = 0.0; counter += 1.0; std::hint::black_box(counter); }\n",
        "fn main() {\n    let mut counter = 0.0;\n\n\n\n    while counter < 10.0 { counter += 1.0; }\n}\n",
        "// let mut counter = 0.0; while counter < 10.0 {}\nfn main() { let _text = \"let mut counter = 0.0; while counter < 10.0 {}\"; }\n",
    ] {
        fixture.write(source.as_bytes());
        for format in ["json", "sonar"] {
            let document = fixture.analyze("sonar-parity", format, 0);
            assert!(
                issues(&document, format)
                    .iter()
                    .all(|issue| rule(issue, format) != KEY),
                "{source}: {document}"
            );
        }
        fixture.assert_source(source.as_bytes());
    }
}

#[test]
fn rust_s2193_cli_incomplete_inputs_preserve_diagnostics_and_source() {
    let fixture = Fixture::new();
    for source in [
        b"fn main() {\n    let mut counter = 0.0;\n    while counter < 10.0 {\n".as_slice(),
        b"fn main() {\xff}\n".as_slice(),
    ] {
        fixture.write(source);
        for format in ["json", "sonar"] {
            let document = fixture.analyze("sonar-parity", format, 2);
            assert_eq!(document["parity"]["completeness"], "incomplete");
            assert!(
                issues(&document, format)
                    .iter()
                    .all(|issue| rule(issue, format) != KEY)
            );
            if source.is_ascii() {
                assert!(
                    issues(&document, format)
                        .iter()
                        .any(|issue| rule(issue, format) == "rust:S2260")
                );
            }
            assert_eq!(fixture.analyze("sonar-parity", format, 2), document);
        }
        fixture.assert_source(source);
    }
    std::fs::remove_file(fixture.0.join(FILE)).expect("remove owned input");
    for format in ["json", "sonar"] {
        let document = fixture.analyze("sonar-parity", format, 2);
        assert_eq!(document["parity"]["completeness"], "incomplete");
        assert!(issues(&document, format).is_empty());
        assert!(!fixture.0.join(FILE).exists());
    }
}

#[test]
fn rust_s2193_cli_unavailable_fix_preserves_source_and_complete_reports() {
    let fixture = Fixture::new();
    fixture.write(ORIGINAL.as_bytes());
    let native = fixture.analyze("strict", "json", 0);
    let generic = fixture.analyze("strict", "sonar", 0);
    for mode in ["--diff", "--apply"] {
        let output = fixture.run(&[
            "fix",
            "--profile",
            "strict",
            "--suggestion",
            "rust:S2193=integer-loop-counter",
            mode,
            "--json",
            FILE,
        ]);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let report: Value = serde_json::from_slice(&output.stdout).expect("refusal report");
        assert_eq!(report["applied"], 0);
        assert_eq!(report["mechanical"], 0);
        assert_eq!(report["files"], json!([]));
        assert!(
            report["warnings"]
                .as_array()
                .expect("warnings")
                .iter()
                .any(|warning| warning
                    .as_str()
                    .is_some_and(|message| message.contains("is unavailable")))
        );
        fixture.assert_source(ORIGINAL.as_bytes());
        assert_eq!(fixture.analyze("strict", "json", 0), native);
        assert_eq!(fixture.analyze("strict", "sonar", 0), generic);
    }
}

#[test]
fn rust_s2193_cli_same_line_loops_match_the_accepted_counter_identifier() {
    let fixture = Fixture::new();
    for (source, ranges) in [
        (
            "fn main() { let mut counter = 0.0; while false {} while counter < 2.0 { counter += 1.0; } }\n",
            vec![(1, 56, 1, 69)],
        ),
        (
            "fn main() { let mut first = 0.0; let mut second = 0.0; while first < 2.0 { first += 1.0; } while second < 2.0 { second += 1.0; } }\n",
            vec![(1, 61, 1, 72), (1, 97, 1, 109)],
        ),
        (
            "fn main() { let mut counter = 0.0; while counter < 2.0 { counter += 1.0; } while counter < 4.0 { counter += 1.0; } }\n",
            vec![(1, 41, 1, 54)],
        ),
    ] {
        fixture.write(source.as_bytes());
        for format in ["json", "sonar"] {
            let document = fixture.analyze("sonar-parity", format, 0);
            let target: Vec<_> = issues(&document, format)
                .into_iter()
                .filter(|issue| rule(issue, format) == KEY)
                .collect();
            let expected: Vec<_> = ranges
                .iter()
                .map(|range| expected(KEY, MESSAGE, *range, format))
                .collect();
            assert_eq!(target, expected.iter().collect::<Vec<_>>(), "{source}");
        }
        fixture.assert_source(source.as_bytes());
    }
}
