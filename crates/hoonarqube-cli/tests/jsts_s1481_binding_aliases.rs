use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::{Command, Output};

const KEY: &str = "javascript:S1481";
const FILE: &str = "case.js";

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-s1481-aliases-{}-{id}",
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

fn assert_clean(source: &str) {
    let fixture = Fixture::new();
    fixture.write(FILE, source.as_bytes());
    for profile in ["default", "sonar-parity", "strict"] {
        for format in ["json", "sonar"] {
            let report = fixture.analyze(FILE, format, profile, 0);
            assert_eq!(
                target_issues(&report, format),
                Vec::<Value>::new(),
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

#[test]
fn express_range_alias_is_clean_in_actual_reports() {
    assert_clean(
        "const req = {};\nreq.range = function range(size, options) {\n  var range = this.get('Range');\n  if (!range) return;\n  return parseRange(size, range, options);\n};\n",
    );
}

#[test]
fn express_subdomains_alias_is_clean_in_actual_reports() {
    assert_clean(
        "const req = {};\ndefineGetter(req, 'subdomains', function subdomains() {\n  var hostname = this.hostname;\n  var offset = this.app.get('subdomain offset');\n  var subdomains = !isIP(hostname)\n    ? hostname.split('.').reverse()\n    : [hostname];\n  return subdomains.slice(offset);\n});\n",
    );
}

#[test]
fn express_colon_index_alias_is_clean_in_actual_reports() {
    assert_clean(
        "function acceptParams(str) {\n  var length = str.length;\n  var colonIndex = str.indexOf(';');\n  var index = colonIndex === -1 ? length : colonIndex;\n  while (index < length) {\n    var colonIndex = str.indexOf(';', index);\n    var endIndex = colonIndex === -1 ? length : colonIndex;\n    index = endIndex + 1;\n  }\n  return index;\n}\nacceptParams('text');\n",
    );
}

#[test]
fn used_var_aliases_keep_hoisting_parameters_recursion_closures_and_write_semantics() {
    for source in [
        "function f() { var value = 1; var value = 2; return value; } f();\n",
        "function f() { { var value = 1; } { var value = 2; } return value; } f();\n",
        "function f() { console.log(value); var value; var value; } f();\n",
        "function f() { var value; var value; return () => value; } f()();\n",
        "function f() { var value; var value; value = 1; } f();\n",
        "function f(value) { var value; return value; } f(1);\n",
        "function f() { function value() {} var value; return value; } f();\n",
        "const api = function recurse(value) { var recurse; return value ? recurse(value - 1) : 0; }; api(1);\n",
    ] {
        assert_clean(source);
    }
}

#[test]
fn unused_aliases_decoys_and_unicode_crlf_keep_exact_objects() {
    let fixture = Fixture::new();
    for source in [
        "function f() {\n  var café = 1;\n  var café = 2;\n  const text = '🦉 café'; // café\n  const obj = { café: 3 };\n  return obj.café + text.length;\n}\nf();\n",
        "function f() {\r\n  var café = 1;\r\n  var café = 2;\r\n  const text = '🦉 café'; // café\r\n  const obj = { café: 3 };\r\n  return obj.café + text.length;\r\n}\r\nf();\r\n",
    ] {
        fixture.write(FILE, source.as_bytes());
        for profile in ["default", "sonar-parity", "strict"] {
            for format in ["json", "sonar"] {
                let report = fixture.analyze(FILE, format, profile, 0);
                assert_eq!(
                    target_issues(&report, format),
                    [
                        expected(
                            "Remove the declaration of the unused 'café' variable.",
                            (2, 6, 10),
                            format
                        ),
                        expected(
                            "Remove the declaration of the unused 'café' variable.",
                            (3, 6, 10),
                            format
                        ),
                    ]
                );
            }
        }
        fixture.assert_source(FILE, source.as_bytes());
    }
}

#[test]
fn invalid_lexical_redeclarations_keep_existing_var_objects() {
    let fixture = Fixture::new();
    for source in [
        "function f() {\n  let value = 1;\n  var value;\n  return value;\n}\nf();\n",
        "function f() {\n  const value = 1;\n  var value;\n  return value;\n}\nf();\n",
        "function f() {\n  class value {}\n  var value;\n  return value;\n}\nf();\n",
    ] {
        fixture.write(FILE, source.as_bytes());
        for format in ["json", "sonar"] {
            let report = fixture.analyze(FILE, format, "strict", 0);
            assert_eq!(
                target_issues(&report, format),
                [expected(
                    "Remove the declaration of the unused 'value' variable.",
                    (3, 6, 11),
                    format
                )]
            );
        }
        fixture.assert_source(FILE, source.as_bytes());
    }
}

#[test]
fn default_parameter_references_keep_body_alias_findings_and_body_predeclaration_reads() {
    let fixture = Fixture::new();
    for (source, name, line, end) in [
        (
            "const api = function self(value = () => self) {\n  var self;\n  return 0;\n};\napi();\n",
            "self",
            2,
            10,
        ),
        (
            "function f(value = () => value) {\n  var value;\n  return 0;\n}\nf();\n",
            "value",
            2,
            11,
        ),
        (
            "function f(input = () => ghost) {\n  var ghost;\n  var ghost;\n  return 0;\n}\nf();\n",
            "ghost",
            3,
            11,
        ),
        (
            "const api = (input = () => ghost) => {\n  var ghost;\n  var ghost;\n  return 0;\n};\napi();\n",
            "ghost",
            3,
            11,
        ),
    ] {
        fixture.write(FILE, source.as_bytes());
        for format in ["json", "sonar"] {
            let report = fixture.analyze(FILE, format, "strict", 0);
            assert_eq!(
                target_issues(&report, format),
                [expected(
                    &format!("Remove the declaration of the unused '{name}' variable."),
                    (line, 6, end),
                    format
                )]
            );
        }
        fixture.assert_source(FILE, source.as_bytes());
    }
    for source in [
        "const api = function self(value = () => self) { console.log(self); var self; return value; }; api();\n",
        "function f(value = () => value) { console.log(value); var value; return 0; } f();\n",
        "function f(input = () => ghost) { console.log(ghost); var ghost; var ghost; return input; } f();\n",
        "const api = (input = () => ghost) => { console.log(ghost); var ghost; var ghost; return input; }; api();\n",
    ] {
        assert_clean(source);
    }
}

#[test]
fn unused_aliases_keep_distinct_function_block_and_self_name_scopes() {
    let fixture = Fixture::new();
    let distinct = concat!(
        "function outer() {\n",
        "  var value = 1;\n",
        "  function inner() {\n",
        "    var value = 2;\n",
        "    var value = 3;\n",
        "    return 0;\n",
        "  }\n",
        "  { let value = 4; console.log(value); }\n",
        "  { let value = 5; }\n",
        "  inner();\n",
        "  return value;\n",
        "}\nouter();\n",
    );
    for (source, targets) in [
        (
            distinct,
            vec![
                (
                    "Remove the declaration of the unused 'value' variable.",
                    (4, 8, 13),
                ),
                (
                    "Remove the declaration of the unused 'value' variable.",
                    (5, 8, 13),
                ),
                (
                    "Remove the declaration of the unused 'value' variable.",
                    (9, 8, 13),
                ),
            ],
        ),
        (
            "const api = function self() {\n  var self = 1;\n  return 2;\n};\napi();\n",
            vec![(
                "Remove the declaration of the unused 'self' variable.",
                (2, 6, 10),
            )],
        ),
        (
            "function api(value) {\n  var value;\n  return 2;\n}\napi(1);\n",
            vec![(
                "Remove the declaration of the unused 'value' variable.",
                (2, 6, 11),
            )],
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
}

#[test]
fn aliases_preserve_ordinary_values_class_lead_and_typescript_silence() {
    let fixture = Fixture::new();
    let ordinary = "function f() {\n  const orphan = 1;\n  function hidden() {}\n  class Hidden {}\n  return 0;\n}\nf();\n";
    for (source, targets) in [
        (
            ordinary,
            vec![
                (
                    "Remove the declaration of the unused 'orphan' variable.",
                    (2, 8, 14),
                ),
                ("Remove this unused function 'hidden'.", (3, 11, 17)),
                ("Remove this unused class 'Hidden'.", (4, 8, 14)),
            ],
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
    let typed =
        "function f(value: number): number { var value; var orphan = 1; return value; } f(1);\n";
    fixture.write("case.ts", typed.as_bytes());
    for format in ["json", "sonar"] {
        let report = fixture.analyze("case.ts", format, "sonar-parity", 0);
        assert_eq!(target_issues(&report, format), Vec::<Value>::new());
    }
    fixture.assert_source("case.ts", typed.as_bytes());
}

#[test]
fn aliases_keep_malformed_and_invalid_utf8_incomplete() {
    let fixture = Fixture::new();
    for bytes in [b"function broken(\n".as_slice(), b"\xff\n".as_slice()] {
        fixture.write(FILE, bytes);
        for format in ["json", "sonar"] {
            let report = fixture.analyze(FILE, format, "sonar-parity", 2);
            assert_eq!(report["parity"]["completeness"], "incomplete");
            assert_eq!(target_issues(&report, format), Vec::<Value>::new());
        }
        fixture.assert_source(FILE, bytes);
    }
}

#[test]
fn aliases_keep_unavailable_remedies_and_repeat_analysis_without_writes() {
    let fixture = Fixture::new();
    let source = "function f() {\n  var used = 1;\n  var used = 2;\n  var orphan = 1;\n  var orphan = 2;\n  return used;\n}\nf();\n";
    fixture.write(FILE, source.as_bytes());
    let native = fixture.analyze(FILE, "json", "strict", 0);
    let generic = fixture.analyze(FILE, "sonar", "strict", 0);
    assert_eq!(
        target_issues(&native, "json"),
        [
            expected(
                "Remove the declaration of the unused 'orphan' variable.",
                (4, 6, 12),
                "json"
            ),
            expected(
                "Remove the declaration of the unused 'orphan' variable.",
                (5, 6, 12),
                "json"
            ),
        ]
    );
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
        fixture.assert_source(FILE, source.as_bytes());
        assert_eq!(fixture.analyze(FILE, "json", "strict", 0), native);
        assert_eq!(fixture.analyze(FILE, "sonar", "strict", 0), generic);
    }
}
