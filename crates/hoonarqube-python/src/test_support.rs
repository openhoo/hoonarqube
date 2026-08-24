//! Shared helpers for analyzer unit tests, used by both the central
//! integration suite in `tests.rs` and the per-rule `tests` modules.

use std::path::PathBuf;

use crate::{AnalyzerOptions, analyze};

pub(crate) fn findings_of(source: &str, key: &str) -> Vec<String> {
    findings(&scan(source), key)
        .into_iter()
        .map(|issue| issue.message.clone())
        .collect()
}

pub(crate) fn regex_finds(source: &str, key: &str) -> bool {
    !findings(&scan(source), key).is_empty()
}

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
    }
}

pub(crate) fn findings<'a>(
    report: &'a hoonarqube_ir::FileReport,
    key: &str,
) -> Vec<&'a hoonarqube_ir::Issue> {
    report
        .issues
        .iter()
        .filter(|issue| issue.rule_key == key)
        .collect()
}

pub(crate) fn scan(source: &str) -> hoonarqube_ir::FileReport {
    analyze(PathBuf::from("t.py"), source, &AnalyzerOptions::default())
}
