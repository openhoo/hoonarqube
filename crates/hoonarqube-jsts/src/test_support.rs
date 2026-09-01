//! Shared test helpers moved from tests.rs (crate-internal, test-only).
pub(crate) use super::AnalyzerOptions;
pub(crate) use super::JstsLanguage;
pub(crate) use super::RuleOptions;
pub(crate) use super::analyze;
pub(crate) use hoonarqube_core::{Language, language_for_extension};
pub(crate) use std::fmt::Write as _;
pub(crate) use std::path::PathBuf;

pub(crate) fn pos(line: u32, column: u32) -> hoonarqube_ir::Pos {
    hoonarqube_ir::Pos { line, column }
}

pub(crate) fn issue(
    rule_key: &str,
    message: &str,
    start: (u32, u32),
    end: (u32, u32),
) -> hoonarqube_ir::Issue {
    hoonarqube_ir::Issue {
        rule_key: rule_key.to_string(),
        message: message.to_string(),
        range: hoonarqube_ir::Range {
            start: pos(start.0, start.1),
            end: pos(end.0, end.1),
        },
        fix: None,
        flows: Vec::new(),
    }
}

pub(crate) fn js(source: &str) -> hoonarqube_ir::FileReport {
    analyze(
        PathBuf::from("test.js"),
        source,
        JstsLanguage::JavaScript,
        &AnalyzerOptions::default(),
    )
}

pub(crate) fn ts(source: &str) -> hoonarqube_ir::FileReport {
    analyze(
        PathBuf::from("test.ts"),
        source,
        JstsLanguage::TypeScript,
        &AnalyzerOptions::default(),
    )
}

pub(crate) fn findings(source: &str, language: JstsLanguage) -> Vec<(String, u32)> {
    analyze(
        PathBuf::from("test.js"),
        source,
        language,
        &AnalyzerOptions::default(),
    )
    .issues
    .into_iter()
    .map(|issue| (issue.rule_key, issue.range.start.line))
    .collect()
}

pub(crate) fn count_key(findings: &[(String, u32)], key: &str) -> usize {
    findings
        .iter()
        .filter(|(key_found, _)| key_found == key)
        .count()
}

pub(crate) fn js_keys(source: &str) -> Vec<(String, u32)> {
    findings(source, JstsLanguage::JavaScript)
}

pub(crate) fn ts_keys(source: &str) -> Vec<(String, u32)> {
    findings_ts(source)
}

pub(crate) fn findings_ts(source: &str) -> Vec<(String, u32)> {
    analyze(
        PathBuf::from("test.ts"),
        source,
        JstsLanguage::TypeScript,
        &AnalyzerOptions::default(),
    )
    .issues
    .into_iter()
    .map(|issue| (issue.rule_key, issue.range.start.line))
    .collect()
}

pub(crate) fn js_with_rules(source: &str, rules: &RuleOptions) -> hoonarqube_ir::FileReport {
    super::analyze_with_rules(
        PathBuf::from("test.js"),
        source,
        JstsLanguage::JavaScript,
        &AnalyzerOptions::default(),
        rules,
    )
}

pub(crate) fn keys_with_rules(source: &str, rules: &RuleOptions) -> Vec<(String, u32)> {
    report_keys(&js_with_rules(source, rules))
}

pub(crate) fn report_keys(report: &hoonarqube_ir::FileReport) -> Vec<(String, u32)> {
    report
        .issues
        .iter()
        .map(|issue| (issue.rule_key.clone(), issue.range.start.line))
        .collect()
}

pub(crate) fn jsx_keys(source: &str) -> Vec<(String, u32)> {
    analyze(
        PathBuf::from("test.jsx"),
        source,
        JstsLanguage::JavaScript,
        &AnalyzerOptions::default(),
    )
    .issues
    .into_iter()
    .map(|issue| (issue.rule_key, issue.range.start.line))
    .collect()
}

pub(crate) fn test_file_keys(source: &str) -> Vec<(String, u32)> {
    analyze(
        PathBuf::from("app.test.js"),
        source,
        JstsLanguage::JavaScript,
        &AnalyzerOptions::default(),
    )
    .issues
    .into_iter()
    .map(|issue| (issue.rule_key, issue.range.start.line))
    .collect()
}

pub(crate) fn mismatched_keys(report: &hoonarqube_ir::FileReport) -> Vec<(String, u32)> {
    report
        .issues
        .iter()
        .map(|i| (i.rule_key.clone(), i.range.start.line))
        .collect()
}

pub(crate) fn matched_keys(report: &hoonarqube_ir::FileReport) -> Vec<(String, u32)> {
    report
        .issues
        .iter()
        .map(|i| (i.rule_key.clone(), i.range.start.line))
        .collect()
}

pub(crate) fn filtered(report: &hoonarqube_ir::FileReport, rule: &str) -> Vec<String> {
    report
        .issues
        .iter()
        .filter(|issue| issue.rule_key.ends_with(rule))
        .map(|issue| {
            format!(
                "{}:{}:{}",
                issue.rule_key, issue.range.start.line, issue.message
            )
        })
        .collect()
}

pub(crate) fn jsx(source: &str) -> hoonarqube_ir::FileReport {
    analyze(
        PathBuf::from("test.jsx"),
        source,
        JstsLanguage::JavaScript,
        &AnalyzerOptions::default(),
    )
}
