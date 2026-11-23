use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

const FULL: &str = r#"<?xml version="1.0" ?>
<coverage version="7.10.7" lines-valid="4" lines-covered="4" branches-valid="2" branches-covered="2">
  <sources><source>/ci/checkout</source></sources>
  <packages><package name="pkg"><classes><class filename="pkg/main.py">
    <methods/>
    <lines>
      <line number="1" hits="1"/>
      <line number="2" hits="1" branch="true" condition-coverage="100% (2/2)"/>
      <line number="3" hits="1"/>
      <line number="4" hits="1"/>
    </lines>
  </class></classes></package></packages>
</coverage>"#;

struct Checkout(PathBuf);

impl Checkout {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "hq-python-cobertura-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("pkg")).unwrap();
        fs::write(
            root.join("pkg/main.py"),
            "def value(enabled):\n    if enabled:\n        return 1\n    return 0\n",
        )
        .unwrap();
        fs::write(
            root.join("gate.json"),
            json!({"schema_version":1,"conditions":[
                {"scope":"overall","metric":"coverage","operator":"gte","threshold":80,"precision":"one_decimal"},
                {"scope":"overall","metric":"line_coverage","operator":"gte","threshold":80,"precision":"one_decimal"},
            ]}).to_string(),
        ).unwrap();
        Self(root)
    }
}

impl Drop for Checkout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scan(root: &Path, args: &[&str]) -> (i32, Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
        .current_dir(root)
        .args([
            "analyze",
            "pkg",
            "--format",
            "json",
            "--profile",
            "sonar-parity",
            "--cache-dir",
            "cache",
            "--quality-gate",
            "gate.json",
        ])
        .args(args)
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|error| {
        panic!(
            "{error}; status={}; stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
    });
    assert_eq!(report["project"]["complete"], true, "{}", report["project"]);
    (out.status.code().unwrap(), report["assessment"].clone())
}

#[test]
fn python_cobertura_produces_pass_fail_and_unavailable_gate_reports() {
    let dir = Checkout::new();
    let xml = dir.0.join("coverage.xml");
    fs::write(&xml, FULL).unwrap();
    let args = ["--coverage-cobertura", "coverage.xml"];
    let (exit, report) = scan(&dir.0, &args);
    assert_eq!(exit, 0, "{report}");
    assert_eq!(report["coverage"]["status"], "complete");
    assert_eq!(report["coverage"]["inputs"][0]["format"], "cobertura");
    assert_eq!(report["coverage"]["files"][0]["path"], "pkg/main.py");
    assert_eq!(report["gate"]["status"], "pass");
    assert_eq!(report["gate"]["conditions"][0]["actual"], 100.0);

    // The same artifact path and bytes must not reuse coverage parsed as Cobertura.
    let (exit, different_format) = scan(&dir.0, &["--coverage-lcov", "coverage.xml"]);
    assert_eq!(exit, 2, "{different_format}");
    assert_eq!(different_format["gate"]["status"], "unavailable");

    let focused = FULL
        .replace("lines-covered=\"4\"", "lines-covered=\"3\"")
        .replace("branches-covered=\"2\"", "branches-covered=\"1\"")
        .replace("100% (2/2)", "50% (1/2)")
        .replace("number=\"4\" hits=\"1\"", "number=\"4\" hits=\"0\"");
    fs::write(&xml, &focused).unwrap();
    let (exit, report) = scan(&dir.0, &args);
    assert_eq!(exit, 1, "{report}");
    assert_eq!(report["coverage"]["status"], "complete");
    assert_eq!(
        report["coverage"]["lines"],
        json!({"eligible":4,"covered":3})
    );
    assert_eq!(
        report["coverage"]["branches"],
        json!({"eligible":2,"covered":1})
    );
    assert_eq!(report["gate"]["status"], "fail");
    assert_eq!(report["gate"]["conditions"][0]["actual"], 66.7);
    assert_eq!(report["gate"]["conditions"][1]["actual"], 75.0);

    for (invalid, diagnostic) in [
        (
            focused.replace("50% (1/2)", "100% (1/2)"),
            "branch percentage contradicts",
        ),
        (
            focused.replace("lines-covered=\"3\"", "lines-covered=\"4\""),
            "summary counters contradict",
        ),
        (
            focused.replace("</coverage>", ""),
            "truncated coverage document",
        ),
    ] {
        fs::write(&xml, invalid).unwrap();
        let (exit, report) = scan(&dir.0, &args);
        assert_eq!(exit, 2, "{report}");
        assert_eq!(report["gate"]["status"], "unavailable");
        assert_eq!(report["coverage"]["status"], "invalid");
        assert!(
            report["coverage"]["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .any(|msg| msg.as_str().unwrap().contains(diagnostic)),
            "{report}"
        );
    }

    fs::remove_file(&xml).unwrap();
    let (exit, report) = scan(&dir.0, &args);
    assert_eq!(exit, 2, "{report}");
    assert_eq!(report["coverage"]["status"], "invalid");
    assert_eq!(report["gate"]["status"], "unavailable");
    let (exit, missing) = scan(&dir.0, &[]);
    assert_eq!(exit, 2, "{missing}");
    assert!(missing.get("coverage").is_none());
    assert_eq!(missing["gate"]["status"], "unavailable");
}
