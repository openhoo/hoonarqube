use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::Command;

const MESSAGE: &str = "Merge this if statement with the nested one.";

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-s1066-outer-else-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("fixture directory");
        Self(path)
    }

    fn analyze(&self, file: &str, format: &str, profile: &str) -> Value {
        let mut args = vec!["analyze", "--format", format];
        if profile != "default" {
            args.extend(["--profile", profile]);
        }
        args.extend(["--", file]);
        let output = Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args(args)
            .output()
            .expect("actual CLI");
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        let report: Value = serde_json::from_slice(&output.stdout).expect("actual report");
        if format == "json" {
            assert_eq!(report["project"]["complete"], true);
            assert_eq!(report["files"].as_array().expect("files").len(), 1);
            assert_eq!(report["files"][0]["path"], file);
            let inventory = report["project"]["files"].as_array().expect("inventory");
            assert_eq!(inventory.len(), 1);
            assert_eq!(inventory[0]["classification"], "source");
            assert_eq!(inventory[0]["status"], "complete");
        }
        report
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn selected(report: &Value, format: &str, key: &str) -> Vec<Value> {
    if format == "json" {
        report["files"][0]["issues"]
            .as_array()
            .expect("native issues")
            .iter()
            .filter(|issue| issue["rule_key"] == key)
            .cloned()
            .collect()
    } else {
        report["issues"]
            .as_array()
            .expect("Generic issues")
            .iter()
            .filter(|issue| issue["ruleId"] == key)
            .cloned()
            .collect()
    }
}

fn expected(key: &str, file: &str, message: &str, line: u32, column: u32, format: &str) -> Value {
    if format == "json" {
        json!({"rule_key":key,"message":message,"range":{"start":{"line":line,"column":column},"end":{"line":line,"column":column+2}}})
    } else {
        json!({"ruleId":key,"primaryLocation":{"filePath":file,"message":message,"textRange":{"startLine":line,"startColumn":column,"endLine":line,"endColumn":column+2}}})
    }
}

fn report_observations(
    report: &Value,
    file: &str,
    language: &str,
    format: &str,
    positions: &[(u32, u32)],
    s6660: &[(u32, u32)],
    utf16_extra: u32,
) -> (Value, Value) {
    let key = format!("{language}:S1066");
    let other_key = format!("{language}:S6660");
    let extra = if format == "sonar" { utf16_extra } else { 0 };
    let expected_s1066: Vec<_> = positions
        .iter()
        .map(|&(line, column)| expected(&key, file, MESSAGE, line, column + extra, format))
        .collect();
    let expected_s6660: Vec<_> = s6660
        .iter()
        .map(|&(line, column)| {
            expected(
                &other_key,
                file,
                "'If' statement should not be the only statement in 'else' block",
                line,
                column,
                format,
            )
        })
        .collect();
    let descriptor_count = if format == "sonar" {
        Some(
            report["rules"]
                .as_array()
                .expect("Generic descriptors")
                .iter()
                .filter(|rule| rule["id"] == key)
                .count(),
        )
    } else {
        None
    };
    let expected_descriptor_count =
        (format == "sonar").then_some(usize::from(!positions.is_empty()));
    (
        json!({"s1066":selected(report, format, &key),"s6660":selected(report, format, &other_key),"s1066_descriptors":descriptor_count}),
        json!({"s1066":expected_s1066,"s6660":expected_s6660,"s1066_descriptors":expected_descriptor_count}),
    )
}

fn assert_reports(source: &str, positions: &[(u32, u32)], s6660: &[(u32, u32)], utf16_extra: u32) {
    let fixture = Fixture::new();
    let mut actual_reports = Vec::new();
    let mut expected_reports = Vec::new();
    for (extension, language) in [("js", "javascript"), ("ts", "typescript")] {
        let file = format!("case.{extension}");
        std::fs::write(fixture.0.join(&file), source).expect("source");
        for profile in ["default", "sonar-parity", "strict"] {
            for format in ["json", "sonar"] {
                let report = fixture.analyze(&file, format, profile);
                let (actual, expected) = report_observations(
                    &report,
                    &file,
                    language,
                    format,
                    positions,
                    s6660,
                    utf16_extra,
                );
                actual_reports.push(json!({"language":language,"profile":profile,"format":format,"observation":actual}));
                expected_reports.push(json!({"language":language,"profile":profile,"format":format,"observation":expected}));
            }
        }
        assert_eq!(
            std::fs::read(fixture.0.join(&file)).expect("source readback"),
            source.as_bytes()
        );
    }
    assert_eq!(actual_reports, expected_reports, "{source}");
}

#[test]
fn outer_else_block_is_clean_in_native_and_generic_reports() {
    assert_reports(
        "if (a) {\n  if (b) { work(); }\n} else {\n  recover();\n}\n",
        &[],
        &[],
        0,
    );
}

#[test]
fn outer_else_if_is_clean_in_native_and_generic_reports() {
    assert_reports(
        "if (a) {\n  if (b) { work(); }\n} else if (c) {\n  recover();\n}\n",
        &[],
        &[],
        0,
    );
}

#[test]
fn outer_empty_else_is_clean_in_native_and_generic_reports() {
    assert_reports("if (a) { if (b) { work(); } } else {}\n", &[], &[], 0);
}

#[test]
fn outer_unbraced_else_is_clean_in_native_and_generic_reports() {
    assert_reports(
        "if (a) { if (b) { work(); } } else recover();\n",
        &[],
        &[],
        0,
    );
}

#[test]
fn inner_else_refusal_remains_clean_in_native_and_generic_reports() {
    assert_reports(
        "if (a) {\n  if (b) { work(); } else { recover(); }\n}\n",
        &[],
        &[],
        0,
    );
}

#[test]
fn genuine_mergeable_pair_keeps_exact_native_and_generic_objects() {
    assert_reports(
        "if (a) {\n  if (b) {\n    work();\n  }\n}\n",
        &[(1, 0)],
        &[],
        0,
    );
}

#[test]
fn outer_else_keeps_exact_mergeable_descendant() {
    assert_reports(
        "if (a) {\n  if (b) {\n    if (c) { work(); }\n  }\n} else { recover(); }\n",
        &[(2, 2)],
        &[],
        0,
    );
}

#[test]
fn final_else_if_arm_keeps_its_own_exact_mergeable_pair() {
    assert_reports(
        "if (a) { one(); }\nelse if (b) {\n  if (c) { two(); }\n}\n",
        &[(2, 5)],
        &[],
        0,
    );
}

#[test]
fn outer_else_keeps_independent_exact_s6660() {
    assert_reports(
        "if (a) {\n  if (b) { one(); }\n} else {\n  if (c) { two(); }\n}\n",
        &[],
        &[(4, 2)],
        0,
    );
}

#[test]
fn multiple_consequent_statements_remain_clean() {
    assert_reports(
        "if (a) {\n  prepare();\n  if (b) { work(); }\n}\n",
        &[],
        &[],
        0,
    );
}

#[test]
fn non_if_consequent_remains_clean() {
    assert_reports("if (a) { work(); }\n", &[], &[], 0);
}

#[test]
fn mixed_crlf_unicode_keeps_exact_scalar_and_utf16_objects() {
    assert_reports(
        "/* 🦉 */ if (a) { if (b) { work(); } } else { recover(); }\r\n/* 🦉 */ if (c) { if (d) { keep(); } }\r\n",
        &[(2, 8)],
        &[],
        1,
    );
}
