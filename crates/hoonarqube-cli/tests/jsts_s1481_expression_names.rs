use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::{Command, Output};

const KEY: &str = "javascript:S1481";
const FILE: &str = "case.js";
const MIXED: &str = concat!(
    "function outer() {\n",
    "  const kept = function innerName() {\n",
    "    const orphan = 1;\n",
    "    function hidden() {}\n",
    "    return 2;\n",
    "  };\n",
    "  return kept;\n",
    "}\nouter();\n",
);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-s1481-expression-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("fixture directory");
        Self(path)
    }

    fn write(&self, file: &str, bytes: &[u8]) {
        std::fs::write(self.0.join(file), bytes).expect("source");
    }

    fn assert_source(&self, file: &str, bytes: &[u8]) {
        assert_eq!(std::fs::read(self.0.join(file)).expect("source"), bytes);
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args(args)
            .output()
            .expect("actual CLI")
    }

    fn analyze(&self, file: &str, format: &str, profile: &str, exit: i32) -> Value {
        let mut args = vec!["analyze", "--format", format];
        if profile != "default" {
            args.extend(["--profile", profile]);
        }
        args.extend(["--", file]);
        let output = self.run(&args);
        assert_eq!(output.status.code(), Some(exit), "{output:?}");
        if exit == 0 {
            assert!(output.stderr.is_empty(), "{output:?}");
        }
        let report: Value = serde_json::from_slice(&output.stdout).expect("actual report");
        if format == "json" {
            assert_eq!(report["project"]["complete"], exit == 0);
        }
        report
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn target_issues(report: &Value, format: &str) -> Vec<Value> {
    if format == "json" {
        report["files"]
            .as_array()
            .expect("native files")
            .iter()
            .flat_map(|file| file["issues"].as_array().expect("native issues"))
            .filter(|issue| issue["rule_key"] == KEY)
            .cloned()
            .collect()
    } else {
        report["issues"]
            .as_array()
            .expect("Generic issues")
            .iter()
            .filter(|issue| issue["ruleId"] == KEY)
            .cloned()
            .collect()
    }
}

fn expected(message: &str, range: (u32, u32, u32), format: &str) -> Value {
    let (line, start, end) = range;
    if format == "json" {
        json!({"rule_key":KEY,"message":message,"range":{"start":{"line":line,"column":start},"end":{"line":line,"column":end}}})
    } else {
        json!({"ruleId":KEY,"primaryLocation":{"filePath":FILE,"message":message,"textRange":{"startLine":line,"startColumn":start,"endLine":line,"endColumn":end}}})
    }
}

#[test]
fn expression_names_are_clean_in_actual_native_and_generic_reports() {
    let fixture = Fixture::new();
    for source in [
        "const app = {};\napp.init = function init() { return app; };\napp.init();\n",
        "[1].map(function callback(value) { return value; });\n",
        "(function initialized() { return 1; })();\n",
        "const api = async function asyncName() { return 1; }; api();\n",
        "const api = function* generatorName() { yield 1; }; api();\n",
        "const owl = '🦉';\r\nconst api = function named() { return owl; };\r\napi();\r\n",
        "const same = 1;\nconst api = function same() { return 2; };\nconsole.log(same); api();\n",
    ] {
        fixture.write(FILE, source.as_bytes());
        for profile in ["default", "sonar-parity", "strict"] {
            for format in ["json", "sonar"] {
                let report = fixture.analyze(FILE, format, profile, 0);
                assert!(
                    target_issues(&report, format).is_empty(),
                    "{source}: {report}"
                );
                if format == "sonar" {
                    assert!(
                        report["rules"]
                            .as_array()
                            .expect("Generic descriptors")
                            .iter()
                            .all(|rule| rule["id"] != KEY)
                    );
                }
            }
        }
        fixture.assert_source(FILE, source.as_bytes());
    }
}

#[test]
fn expression_names_preserve_nested_and_outer_unused_bindings() {
    let fixture = Fixture::new();
    for source in [MIXED.to_string(), MIXED.replace('\n', "\r\n")] {
        fixture.write(FILE, source.as_bytes());
        for format in ["json", "sonar"] {
            let report = fixture.analyze(FILE, format, "strict", 0);
            assert_eq!(
                target_issues(&report, format),
                [
                    expected(
                        "Remove the declaration of the unused 'orphan' variable.",
                        (3, 10, 16),
                        format
                    ),
                    expected("Remove this unused function 'hidden'.", (4, 13, 19), format),
                ]
            );
        }
        fixture.assert_source(FILE, source.as_bytes());
    }
    let source = "function outer() {\n  const orphan = function selfName() { return 1; };\n  return 2;\n}\nouter();\n";
    fixture.write(FILE, source.as_bytes());
    for format in ["json", "sonar"] {
        let report = fixture.analyze(FILE, format, "sonar-parity", 0);
        assert_eq!(
            target_issues(&report, format),
            [expected(
                "Remove the declaration of the unused 'orphan' variable.",
                (2, 8, 14),
                format
            )]
        );
    }
    fixture.assert_source(FILE, source.as_bytes());
}

#[test]
fn expression_names_preserve_recursive_declaration_class_and_typescript_controls() {
    let fixture = Fixture::new();
    for (source, targets) in [
        (
            "const factorial = function recurse(value) { return value === 0 ? 1 : value * recurse(value - 1); }; factorial(3);\n",
            vec![],
        ),
        (
            "// function namedComment() {}\nconst text = 'function namedText() {}';\nconsole.log(text);\n",
            vec![],
        ),
        (
            "function outer() {\n  function orphan() { return 1; }\n  return 2;\n}\nouter();\n",
            vec![("Remove this unused function 'orphan'.", (2, 11, 17))],
        ),
        (
            "const exportedClass = class NamedClass {};\nnew exportedClass();\n",
            vec![("Remove this unused class 'NamedClass'.", (1, 28, 38))],
        ),
    ] {
        fixture.write(FILE, source.as_bytes());
        for format in ["json", "sonar"] {
            let report = fixture.analyze(FILE, format, "strict", 0);
            assert_eq!(
                target_issues(&report, format),
                targets
                    .iter()
                    .map(|(message, range)| expected(message, *range, format))
                    .collect::<Vec<_>>()
            );
        }
        fixture.assert_source(FILE, source.as_bytes());
    }
    let typed = "const api = function typed(value: number): number { return value; }; api(1);\n";
    fixture.write("case.ts", typed.as_bytes());
    for format in ["json", "sonar"] {
        let report = fixture.analyze("case.ts", format, "sonar-parity", 0);
        assert!(target_issues(&report, format).is_empty());
    }
    fixture.assert_source("case.ts", typed.as_bytes());
}

#[test]
fn expression_names_keep_malformed_and_invalid_utf8_incomplete() {
    let fixture = Fixture::new();
    for bytes in [b"function broken(\n".as_slice(), b"\xff\n".as_slice()] {
        fixture.write(FILE, bytes);
        for format in ["json", "sonar"] {
            let report = fixture.analyze(FILE, format, "sonar-parity", 2);
            assert_eq!(report["parity"]["completeness"], "incomplete");
            assert!(target_issues(&report, format).is_empty());
        }
        fixture.assert_source(FILE, bytes);
    }
}

#[test]
fn expression_names_keep_unavailable_remedies_and_repeat_analysis_without_writes() {
    let fixture = Fixture::new();
    fixture.write(FILE, MIXED.as_bytes());
    let native = fixture.analyze(FILE, "json", "strict", 0);
    let generic = fixture.analyze(FILE, "sonar", "strict", 0);
    for issue in target_issues(&native, "json") {
        assert!(issue.get("fix").is_none());
        assert!(issue.get("alternatives").is_none());
        assert!(issue.get("flows").is_none());
    }
    for mode in ["--diff", "--apply"] {
        let output = fixture.run(&[
            "fix",
            "--json",
            "--profile",
            "strict",
            "--rule",
            KEY,
            "--suggestion",
            "javascript:S1481=remove-unused-name",
            mode,
            FILE,
        ]);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let refusal: Value = serde_json::from_slice(&output.stdout).expect("refusal report");
        assert_eq!(refusal["applied"], 0);
        assert_eq!(refusal["mechanical"], 0);
        assert_eq!(refusal["files"], json!([]));
        assert!(
            refusal["warnings"]
                .as_array()
                .expect("warnings")
                .iter()
                .any(|warning| warning
                    .as_str()
                    .is_some_and(|message| message.contains("is unavailable")))
        );
        fixture.assert_source(FILE, MIXED.as_bytes());
        assert_eq!(fixture.analyze(FILE, "json", "strict", 0), native);
        assert_eq!(fixture.analyze(FILE, "sonar", "strict", 0), generic);
    }
}
