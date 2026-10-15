use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::{Command, Output};

const KEY: &str = "csharpsquid:S1109";
// Complete controls executed by the pinned installed Sonar analyzer.
const CONTROL: &str = r#"using System.Collections.Generic;
namespace Scope;
class Cases
{
    int[] A = new[] {
        1, 2 };
    Dictionary<int, int> D = new() {
        [1] = 2 };
    List<int> L = new() {
        1, 2 };
    Cases O = new Cases {
        Value = 1 };
    object Anonymous = new {
        X = 1 };
    public int Value { get; set; }
    void Block()
    {
        _ = A.Length; }
    void Good()
    {
        _ = A.Length;
    }
    void Inline() { _ = A.Length; }
}
"#;
const NESTED: &str = r"using System;
namespace Scope;
class Nested
{
    Func<int>[] F = {
        () => {
            return 1; } };
}
";

struct Fixture(PathBuf);

impl Fixture {
    fn new(label: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-s1109-{label}-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("owned fixture directory");
        Self(path)
    }

    fn write(&self, source: &[u8]) {
        std::fs::write(self.0.join("Control.cs"), source).expect("fixture source");
    }

    fn source(&self) -> Vec<u8> {
        std::fs::read(self.0.join("Control.cs")).expect("source readback")
    }

    fn analyze(&self, format: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args([
                "analyze",
                "--profile",
                "sonar-parity",
                "--format",
                format,
                "--cache-dir",
                "cache",
                "--",
                "Control.cs",
            ])
            .output()
            .expect("actual CLI")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn document(output: &Output, exit: i32) -> Value {
    assert_eq!(output.status.code(), Some(exit), "{output:?}");
    serde_json::from_slice(&output.stdout).expect("one complete JSON document")
}

fn targets(report: &Value, format: &str) -> Vec<Value> {
    if format == "json" {
        report["files"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|file| file["issues"].as_array().unwrap())
            .filter(|issue| issue["rule_key"] == KEY)
            .cloned()
            .collect()
    } else {
        report["issues"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|issue| issue["ruleId"] == KEY)
            .cloned()
            .collect()
    }
}

fn expected(format: &str, line: u32, column: u32) -> Value {
    let message = "Move this closing curly brace to the next line.";
    if format == "json" {
        json!({"rule_key":KEY,"message":message,"range":{"start":{"line":line,"column":column},"end":{"line":line,"column":column+1}}})
    } else {
        json!({"ruleId":KEY,"primaryLocation":{"filePath":"Control.cs","message":message,"textRange":{"startLine":line,"startColumn":column,"endLine":line,"endColumn":column+1}}})
    }
}

fn complete_inventory(report: &Value, format: &str) {
    if format == "json" {
        assert_eq!(report["project"]["complete"], true);
        assert_eq!(report["files"].as_array().unwrap().len(), 1);
        assert_eq!(report["files"][0]["path"], "Control.cs");
    }
    assert_eq!(report["parity"]["semantic_context"]["csharp"], "missing");
    assert_eq!(report["parity"]["completeness"], "incomplete");
    assert_eq!(report["parity"]["rule_set_violations"], json!([]));
}

#[test]
fn csharp_s1109_cli_exempts_five_initializer_forms_and_retains_multiline_block() {
    let fixture = Fixture::new("initializers");
    fixture.write(CONTROL.as_bytes());
    for format in ["json", "sonar"] {
        let output = fixture.analyze(format);
        assert!(output.stderr.is_empty(), "{output:?}");
        let report = document(&output, 0);
        complete_inventory(&report, format);
        assert_eq!(targets(&report, format), vec![expected(format, 18, 22)]);
    }
    assert_eq!(fixture.source(), CONTROL.as_bytes());
}

#[test]
fn csharp_s1109_cli_keeps_initializer_only_control_clean() {
    let fixture = Fixture::new("clean");
    let source = CONTROL.replace("_ = A.Length; }", "_ = A.Length;\n    }");
    fixture.write(source.as_bytes());
    for format in ["json", "sonar"] {
        let report = document(&fixture.analyze(format), 0);
        complete_inventory(&report, format);
        assert!(targets(&report, format).is_empty());
    }
    assert_eq!(fixture.source(), source.as_bytes());
}

#[test]
fn csharp_s1109_cli_retains_lambda_block_inside_array_initializer() {
    let fixture = Fixture::new("nested");
    fixture.write(NESTED.as_bytes());
    for format in ["json", "sonar"] {
        let report = document(&fixture.analyze(format), 0);
        complete_inventory(&report, format);
        assert_eq!(targets(&report, format), vec![expected(format, 7, 22)]);
    }
    assert_eq!(fixture.source(), NESTED.as_bytes());
}

#[test]
fn csharp_s1109_cli_preserves_scalar_and_utf16_columns_with_crlf() {
    let fixture = Fixture::new("unicode");
    let source = format!("// 😀 café\n{CONTROL}")
        .replace("Cases", "Café")
        .replace("_ = A.Length; }", "_ = \"😀\".Length; }")
        .replace('\n', "\r\n");
    fixture.write(source.as_bytes());
    for format in ["json", "sonar"] {
        let report = document(&fixture.analyze(format), 0);
        complete_inventory(&report, format);
        let column = if format == "json" { 24 } else { 25 };
        assert_eq!(targets(&report, format), vec![expected(format, 19, column)]);
    }
    assert_eq!(fixture.source(), source.as_bytes());
}

#[test]
fn csharp_s1109_cli_cache_reanalysis_preserves_exact_changed_block_roles() {
    let fixture = Fixture::new("cache");
    let clean = CONTROL.replace("_ = A.Length; }", "_ = A.Length;\n    }");
    for format in ["json", "sonar"] {
        fixture.write(clean.as_bytes());
        let first = document(&fixture.analyze(format), 0);
        complete_inventory(&first, format);
        assert!(targets(&first, format).is_empty());
        assert_eq!(first, document(&fixture.analyze(format), 0));
        fixture.write(NESTED.as_bytes());
        let changed = document(&fixture.analyze(format), 0);
        complete_inventory(&changed, format);
        assert_eq!(targets(&changed, format), vec![expected(format, 7, 22)]);
        assert_eq!(changed, document(&fixture.analyze(format), 0));
        fixture.write(clean.as_bytes());
        assert_eq!(first, document(&fixture.analyze(format), 0));
    }
    assert_eq!(fixture.source(), clean.as_bytes());
}

#[test]
fn csharp_s1109_cli_preserves_malformed_and_invalid_utf8_incompleteness() {
    let fixture = Fixture::new("incomplete");
    for source in [
        b"class Broken\n{\n int[] X = new[] {\n 1, 2 };\n void M(\n".as_slice(),
        b"class Broken {\xff}\n".as_slice(),
    ] {
        fixture.write(source);
        for format in ["json", "sonar"] {
            let report = document(&fixture.analyze(format), 2);
            assert_eq!(report["parity"]["completeness"], "incomplete");
            if format == "json" {
                assert_eq!(report["project"]["complete"], false);
                assert!(!report["project"]["warnings"].as_array().unwrap().is_empty());
            }
            assert!(targets(&report, format).is_empty());
        }
        assert_eq!(fixture.source(), source);
    }
}
