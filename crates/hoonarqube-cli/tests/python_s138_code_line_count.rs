use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::{Value, json};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-s138-code-lines-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("fixture directory");
        Self(path)
    }

    fn run(&self, profile: &str, format: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
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
            .expect("run hoonarqube")
    }

    fn analyze(&self, source: &str, profile: &str, format: &str) -> Value {
        std::fs::write(self.0.join("case.py"), source).expect("source");
        let output = self.run(profile, format);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        assert_eq!(
            std::fs::read(self.0.join("case.py")).expect("readback"),
            source.as_bytes()
        );
        let report: Value = serde_json::from_slice(&output.stdout).expect("report");
        assert_accounting(&report, profile, format);
        report
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn assert_accounting(report: &Value, profile: &str, format: &str) {
    if format == "json" {
        assert_eq!(report["project"]["complete"], true);
        assert_eq!(report["project"]["metrics"]["files"], 1);
        assert_eq!(report["project"]["warnings"], json!([]));
        assert_eq!(report["project"]["files"][0]["path"], "case.py");
        assert_eq!(report["project"]["files"][0]["classification"], "source");
        assert_eq!(report["project"]["files"][0]["status"], "complete");
        assert_eq!(report["project"]["files"][0]["reason"], Value::Null);
    }
    assert_eq!(report.get("parity").is_some(), profile == "sonar-parity");
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
        .filter(|issue| issue[key] == "python:S138")
        .cloned()
        .collect()
}

#[derive(Clone, Copy)]
struct Expected {
    name: &'static str,
    kind: &'static str,
    count: u32,
    line: u32,
    col: u32,
}

fn expected(format: &str, target: &Expected) -> Value {
    let Expected {
        name,
        kind,
        count,
        line,
        col,
    } = target;
    let end = col + u32::try_from(name.len()).expect("name length");
    let message = format!(
        "This {kind} \"{name}\" has {count} lines of code, which is greater than \
         the 100 authorized. Split it into smaller {kind}s."
    );
    if format == "json" {
        json!({"rule_key":"python:S138", "message":message,
            "range":{"start":{"line":line,"column":col},"end":{"line":line,"column":end}}})
    } else {
        json!({"ruleId":"python:S138", "primaryLocation":{"filePath":"case.py",
            "message":message,"textRange":{"startLine":line,"endLine":line,
            "startColumn":col,"endColumn":end}}})
    }
}

fn body(count: u32, indent: &str, padding: bool) -> String {
    let mut source = String::new();
    for number in 0..count {
        source.push_str(&format!("{indent}consume({number})\n"));
        if padding {
            source.push_str(&format!("\n{indent}# comment after logical newline\n"));
        }
    }
    source
}

fn assert_source(source: &str, expected_targets: &[Expected], format: &str) {
    let fixture = Fixture::new();
    for profile in ["strict", "sonar-parity"] {
        let report = fixture.analyze(source, profile, format);
        assert_eq!(
            targets(&report, format),
            expected_targets
                .iter()
                .map(|target| expected(format, target))
                .collect::<Vec<_>>(),
            "{profile}/{format}"
        );
    }
}

fn function(name: &'static str, count: u32, line: u32, col: u32) -> Expected {
    Expected {
        name,
        kind: "function",
        count,
        line,
        col,
    }
}

fn assert_boundaries(format: &str) {
    let clean = format!("def work():\n{}", body(100, "    ", true));
    assert_source(&clean, &[], format);
    let positive = format!("def work():\n{}", body(101, "    ", true));
    assert_source(&positive, &[function("work", 101, 1, 4)], format);
    let contiguous = format!("def work():\n{}", body(101, "    ", false));
    assert_source(&contiguous, &[function("work", 101, 1, 4)], format);
}

#[test]
fn native_counts_only_code_lines_at_the_100_and_101_boundaries() {
    assert_boundaries("json");
}

#[test]
fn generic_counts_only_code_lines_at_the_100_and_101_boundaries() {
    assert_boundaries("sonar");
}

fn multiline_string(prefix: &str) -> String {
    format!("{prefix}\"\"\"first\n{}last\"\"\"\n", "\n".repeat(99))
}

#[test]
fn own_docstrings_are_removed_and_other_multiline_literals_keep_their_lines() {
    let docstring = format!(
        "def work():\n{}{}",
        multiline_string("    "),
        body(100, "    ", false)
    );
    let literal = format!(
        "def work():\n{}    return value\n",
        multiline_string("    value = ")
    );
    for format in ["json", "sonar"] {
        assert_source(&docstring, &[], format);
        assert_source(&literal, &[function("work", 102, 1, 4)], format);
    }
}

#[test]
fn lexical_methods_and_nested_functions_use_exact_messages_and_ranges() {
    let method = format!(
        "class Worker:\n    def work(self):\n{}",
        body(101, "        ", true)
    );
    let nested = format!(
        "class Worker:\n    def outer(self):\n        def inner():\n{}        return inner\n",
        body(101, "            ", false)
    );
    let work = Expected {
        kind: "method",
        ..function("work", 101, 2, 8)
    };
    let outer = Expected {
        kind: "method",
        ..function("outer", 103, 2, 8)
    };
    for format in ["json", "sonar"] {
        assert_source(&method, std::slice::from_ref(&work), format);
        assert_source(&nested, &[outer, function("inner", 101, 3, 12)], format);
    }
}

fn assert_incomplete(fixture: &Fixture, profile: &str, format: &str) {
    let output = fixture.run(profile, format);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(!output.stderr.is_empty(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("incomplete report");
    if format == "json" {
        assert_eq!(report["project"]["complete"], false);
        assert_ne!(report["project"]["files"][0]["status"], "complete");
    }
    assert!(targets(&report, format).is_empty());
    assert_eq!(
        std::fs::read(fixture.0.join("case.py")).expect("readback"),
        b"value =\n"
    );
}

#[test]
fn malformed_assignment_keeps_exit_two_diagnostics_and_source_bytes() {
    let fixture = Fixture::new();
    std::fs::write(fixture.0.join("case.py"), "value =\n").expect("source");
    for profile in ["strict", "sonar-parity"] {
        for format in ["json", "sonar"] {
            assert_incomplete(&fixture, profile, format);
        }
    }
}
