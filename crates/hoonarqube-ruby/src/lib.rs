//! Tolerant Tree-sitter Ruby frontend.
//!
//! This crate deliberately separates parsing and semantic facts from findings:
//! Ruby rules are not registered in the current catalog, so [`analyze`] emits
//! a complete report with deterministic metrics and no invented issues. The
//! owned [`RubyFacts`] model remains available to rule registration work.

use std::path::PathBuf;

use hoonarqube_ir::FileReport;

pub mod context;
pub mod engine;
pub mod support;

pub use context::*;
pub use engine::analyze_facts;

/// Configuration knobs retained for parity with other language frontends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzerOptions {
    pub maximum_line_length: usize,
    pub maximum_lines_of_code: usize,
    pub maximum_function_parameters: usize,
    pub maximum_function_lines: usize,
    pub maximum_nesting_depth: usize,
    pub maximum_cognitive_complexity: usize,
    pub duplicate_string_threshold: usize,
}

impl Default for AnalyzerOptions {
    fn default() -> Self {
        Self {
            maximum_line_length: 120,
            maximum_lines_of_code: 1000,
            maximum_function_parameters: 7,
            maximum_function_lines: 100,
            maximum_nesting_depth: 4,
            maximum_cognitive_complexity: 15,
            duplicate_string_threshold: 3,
        }
    }
}

/// Analyze one Ruby source file without fabricating unregistered rule issues.
#[must_use]
pub fn analyze(path: PathBuf, source: &str, options: &AnalyzerOptions) -> FileReport {
    let _ = options;
    let facts = analyze_facts(source);
    FileReport {
        path,
        language: "ruby".to_string(),
        issues: Vec::new(),
        metrics: facts.metrics.file,
    }
}

/// Exact `CodeQL` query IDs emitted by [`analyze_github_quality`], in sorted order.
pub const GITHUB_QUALITY_RULE_IDS: &[&str] = &[
    "rb/database-query-in-loop",
    "rb/uninitialized-local-variable",
    "rb/useless-assignment-to-local",
];

/// Hook for independently registered GitHub-quality rules.
///
/// Ruby rules are implemented conservatively and are intentionally separate
/// from [`analyze`], because the current Sonar catalog has no Ruby entries.
#[must_use]
pub fn analyze_github_quality(source: &str) -> Vec<hoonarqube_ir::Issue> {
    engine::github_quality(source)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn github_quality_rules_are_deterministic_and_conservative() {
        let useless = analyze_github_quality("def f\n  unused = 1\nend\n");
        assert!(
            useless
                .iter()
                .any(|issue| issue.rule_key == "rb/useless-assignment-to-local")
        );

        let uninitialized = analyze_github_quality("def f\n  value.length\nend\n");
        assert!(
            uninitialized
                .iter()
                .any(|issue| issue.rule_key == "rb/uninitialized-local-variable")
        );
        assert!(
            analyze_github_quality("def f\n  value.to_s\nend\n")
                .iter()
                .all(|issue| issue.rule_key != "rb/uninitialized-local-variable")
        );

        let query = analyze_github_quality(
            "class User < ApplicationRecord; end\nitems.each { User.where(active: true) }\n",
        );
        assert!(
            query
                .iter()
                .any(|issue| issue.rule_key == "rb/database-query-in-loop")
        );
        assert_eq!(
            query,
            analyze_github_quality(
                "class User < ApplicationRecord; end\nitems.each { User.where(active: true) }\n"
            )
        );
    }

    #[test]
    fn report_contract_preserves_path_language_and_metrics() {
        let report = analyze(
            PathBuf::from("lib/example.rb"),
            "# comment\nx = 1\n",
            &AnalyzerOptions::default(),
        );
        assert_eq!(report.path, PathBuf::from("lib/example.rb"));
        assert_eq!(report.language, "ruby");
        assert!(report.issues.is_empty());
        assert_eq!(report.metrics.lines, 2);
        assert_eq!(report.metrics.comment_lines, 1);
        assert_eq!(report.metrics.code_lines, 1);
    }

    #[test]
    fn malformed_input_is_safe_and_still_has_metrics() {
        let facts = analyze_facts("def broken(\n  value = \n");
        assert!(facts.malformed);
        assert!(facts.metrics.file.lines > 0);
        let report = analyze(
            PathBuf::from("broken.rb"),
            "def broken(\n",
            &AnalyzerOptions::default(),
        );
        assert!(report.issues.is_empty());
    }
}
