use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::Command;

const MESSAGE: &str = "Merge this if statement with the nested one.";

struct ExpectedPair {
    primary: (u32, u32),
    nested: (u32, u32),
    utf16_extra: (u32, u32),
}

const fn pair(primary: (u32, u32), nested: (u32, u32)) -> ExpectedPair {
    ExpectedPair {
        primary,
        nested,
        utf16_extra: (0, 0),
    }
}

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

fn expected_pair(key: &str, file: &str, pair: &ExpectedPair, format: &str) -> Value {
    let (primary_extra, nested_extra) = if format == "sonar" {
        pair.utf16_extra
    } else {
        (0, 0)
    };
    let mut issue = expected(
        key,
        file,
        MESSAGE,
        pair.primary.0,
        pair.primary.1 + primary_extra,
        format,
    );
    let (line, column) = (pair.nested.0, pair.nested.1 + nested_extra);
    if format == "json" {
        issue["flows"] = json!([{"locations":[{"message":"Nested \"if\" statement.","range":{"start":{"line":line,"column":column},"end":{"line":line,"column":column+2}}}]}]);
    } else {
        issue["secondaryLocations"] = json!([{"filePath":file,"message":"Nested \"if\" statement.","textRange":{"startLine":line,"startColumn":column,"endLine":line,"endColumn":column+2}}]);
    }
    issue
}

fn report_observations(
    report: &Value,
    file: &str,
    language: &str,
    format: &str,
    pairs: &[ExpectedPair],
    s6660: &[(u32, u32)],
) -> (Value, Value) {
    let key = format!("{language}:S1066");
    let other_key = format!("{language}:S6660");
    let expected_s1066: Vec<_> = pairs
        .iter()
        .map(|pair| expected_pair(&key, file, pair, format))
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
    let expected_descriptor_count = (format == "sonar").then_some(usize::from(!pairs.is_empty()));
    (
        json!({"s1066":selected(report, format, &key),"s6660":selected(report, format, &other_key),"s1066_descriptors":descriptor_count}),
        json!({"s1066":expected_s1066,"s6660":expected_s6660,"s1066_descriptors":expected_descriptor_count}),
    )
}

fn assert_reports(source: &str, pairs: &[ExpectedPair], s6660: &[(u32, u32)]) {
    let fixture = Fixture::new();
    let mut actual_reports = Vec::new();
    let mut expected_reports = Vec::new();
    for (extension, language) in [("js", "javascript"), ("ts", "typescript")] {
        let file = format!("case.{extension}");
        std::fs::write(fixture.0.join(&file), source).expect("source");
        for profile in ["default", "sonar-parity", "strict"] {
            for format in ["json", "sonar"] {
                let report = fixture.analyze(&file, format, profile);
                let (actual, expected) =
                    report_observations(&report, &file, language, format, pairs, s6660);
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
    );
}

#[test]
fn outer_else_if_is_clean_in_native_and_generic_reports() {
    assert_reports(
        "if (a) {\n  if (b) { work(); }\n} else if (c) {\n  recover();\n}\n",
        &[],
        &[],
    );
}

#[test]
fn outer_empty_else_is_clean_in_native_and_generic_reports() {
    assert_reports("if (a) { if (b) { work(); } } else {}\n", &[], &[]);
}

#[test]
fn outer_unbraced_else_is_clean_in_native_and_generic_reports() {
    assert_reports("if (a) { if (b) { work(); } } else recover();\n", &[], &[]);
}

#[test]
fn inner_else_refusal_remains_clean_in_native_and_generic_reports() {
    assert_reports(
        "if (a) {\n  if (b) { work(); } else { recover(); }\n}\n",
        &[],
        &[],
    );
}

#[test]
fn genuine_mergeable_pair_keeps_exact_native_and_generic_objects() {
    assert_reports(
        "if (a) {\n  if (b) {\n    work();\n  }\n}\n",
        &[pair((1, 0), (2, 2))],
        &[],
    );
}

#[test]
fn outer_else_keeps_exact_mergeable_descendant() {
    assert_reports(
        "if (a) {\n  if (b) {\n    if (c) { work(); }\n  }\n} else { recover(); }\n",
        &[pair((2, 2), (3, 4))],
        &[],
    );
}

#[test]
fn final_else_if_arm_keeps_its_own_exact_mergeable_pair() {
    assert_reports(
        "if (a) { one(); }\nelse if (b) {\n  if (c) { two(); }\n}\n",
        &[pair((2, 5), (3, 2))],
        &[],
    );
}

#[test]
fn outer_else_keeps_independent_exact_s6660() {
    assert_reports(
        "if (a) {\n  if (b) { one(); }\n} else {\n  if (c) { two(); }\n}\n",
        &[],
        &[(4, 2)],
    );
}

#[test]
fn multiple_consequent_statements_remain_clean() {
    assert_reports(
        "if (a) {\n  prepare();\n  if (b) { work(); }\n}\n",
        &[],
        &[],
    );
}

#[test]
fn non_if_consequent_remains_clean() {
    assert_reports("if (a) { work(); }\n", &[], &[]);
}

#[test]
fn mixed_crlf_unicode_keeps_exact_scalar_and_utf16_objects() {
    assert_reports(
        "/* 🦉 */ if (a) { if (b) { work(); } } else { recover(); }\r\n/* 🦉 */ if (c) { if (d) { keep(); } }\r\n",
        &[ExpectedPair {
            primary: (2, 8),
            nested: (2, 17),
            utf16_extra: (1, 1),
        }],
        &[],
    );
}

#[test]
fn chain_supporting_locations_point_only_to_each_immediate_child() {
    assert_reports(
        "if (a) {\n  if (b) {\n    if (c) {\n      if (d) { work(); }\n    }\n  }\n}\n",
        &[
            pair((1, 0), (2, 2)),
            pair((2, 2), (3, 4)),
            pair((3, 4), (4, 6)),
        ],
        &[],
    );
}

#[test]
fn supporting_locations_convert_distinct_unicode_prefixes_across_crlf_lines() {
    assert_reports(
        "/* 🦉 */ if (skip) { if (guard) { skip(); } } else { recover(); }\r\n/* 🦉 */ if (a) {\r\n  /* 🦉🦉 */ if (b) { work(); }\r\n}\r\n",
        &[ExpectedPair {
            primary: (2, 8),
            nested: (3, 11),
            utf16_extra: (1, 2),
        }],
        &[],
    );
}

#[test]
fn supporting_locations_do_not_attach_to_independent_s6660() {
    assert_reports(
        "if (a) { if (b) { work(); } }\nif (c) { other(); } else {\n  if (d) { next(); }\n}\n",
        &[pair((1, 0), (1, 9))],
        &[(3, 2)],
    );
}

#[test]
fn empty_source_has_no_supporting_location_or_descriptor() {
    assert_reports("", &[], &[]);
}

#[test]
fn unbraced_consequent_residual_is_unchanged() {
    assert_reports("if (a) if (b) { work(); }\n", &[], &[]);
}

#[test]
fn supporting_locations_create_no_automatic_edit() {
    let fixture = Fixture::new();
    let source = "if (a) {\n  if (b) { work(); }\n}\n";
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for (extension, language) in [("js", "javascript"), ("ts", "typescript")] {
        let file = format!("case.{extension}");
        std::fs::write(fixture.0.join(&file), source).expect("source");
        let key = format!("{language}:S1066");
        for profile in ["default", "sonar-parity", "strict"] {
            let native = fixture.analyze(&file, "json", profile);
            let generic = fixture.analyze(&file, "sonar", profile);
            for mode in ["--diff", "--apply"] {
                let mut args = vec!["fix", "--json", "--rule", &key, mode];
                if profile != "default" {
                    args.extend(["--profile", profile]);
                }
                args.push(&file);
                let output = Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
                    .current_dir(&fixture.0)
                    .args(args)
                    .output()
                    .expect("actual fix CLI");
                assert_eq!(output.status.code(), Some(0), "{output:?}");
                assert!(output.stderr.is_empty(), "{output:?}");
                let report: Value = serde_json::from_slice(&output.stdout).expect("fix report");
                actual.push(report);
                expected.push(if mode == "--diff" {
                    json!({"files":[],"planned":0,"applicable":0,"skipped":0,"mechanical":0,"applied":0,"verified":0,"unverified":0,"warnings":[]})
                } else {
                    json!({"files":[],"applied":0,"skipped":0,"mechanical":0,"verified":0,"unverified":0,"regressions":0,"warnings":[]})
                });
                assert_eq!(
                    std::fs::read(fixture.0.join(&file)).expect("source"),
                    source.as_bytes()
                );
                assert_eq!(fixture.analyze(&file, "json", profile), native);
                assert_eq!(fixture.analyze(&file, "sonar", profile), generic);
            }
        }
    }
    assert_eq!(actual, expected);
}
