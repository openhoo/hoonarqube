//! Tolerant Tree-sitter Ruby frontend.
//!
//! This crate deliberately separates parsing and semantic facts from
//! findings. The sonar-parity route ([`analyze`]) runs the cataloged
//! Ruby detectors from [`rules`] over the frozen `hoonarqube-catalog`
//! surface; the owned [`RubyFacts`] model remains available to further rule
//! registration work.

use std::path::PathBuf;

use hoonarqube_ir::FileReport;

pub mod context;
pub mod engine;
mod rules;
pub mod support;

pub use context::*;
pub use engine::analyze_facts;

/// Knobs for the Ruby analyzer; defaults mirror the frozen catalog rule
/// parameters. The sonar-parity route consumes `duplicate_string_threshold`
/// (`ruby:S1192` catalog default `3`); the remaining knobs are retained for
/// parity with the other language frontends as further rules register.
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

/// Analyze one Ruby source file with the cataloged sonar-parity detectors.
///
/// Reports stay deterministic: parse errors fail closed (metrics only, no
/// findings on recovered fragments), and the route never fabricates issues
/// for rules outside the frozen catalog. Ruby has no reference-side test
/// detection, so MAIN-scope rules apply to every analyzed source — the
/// pinned `rake` oracle reports `ruby:S1192` under `test/` as well.
#[must_use]
pub fn analyze(path: PathBuf, source: &str, options: &AnalyzerOptions) -> FileReport {
    let mut issues = Vec::new();
    if let Some(tree) = engine::parse_source(source) {
        issues.extend(rules::check_sonar_rules(&tree, source, options));
    }
    hoonarqube_ir::sort_issues(&mut issues);
    issues.dedup();
    FileReport {
        path,
        language: "ruby".to_string(),
        issues,
        metrics: support::lexical_metrics(source),
    }
}

/// Exact `CodeQL` query IDs emitted by [`analyze_github_quality`], in sorted order.
pub const GITHUB_QUALITY_RULE_IDS: &[&str] = &[
    "rb/database-query-in-loop",
    "rb/uninitialized-local-variable",
    "rb/useless-assignment-to-local",
];

/// Hook for independently registered GitHub-quality rules.
/// Ruby rules are implemented conservatively and are intentionally separate
/// from [`analyze`], which owns the sonar-parity route.
#[must_use]
pub fn analyze_github_quality(source: &str) -> Vec<hoonarqube_ir::Issue> {
    engine::github_quality(source)
}

/// Runs GitHub Code Quality queries with the same lexical metrics as [`analyze`].
#[must_use]
pub fn analyze_github_quality_report(path: PathBuf, source: &str) -> FileReport {
    FileReport {
        path,
        language: "ruby".to_owned(),
        issues: analyze_github_quality(source),
        metrics: support::lexical_metrics(source),
    }
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

        let uninitialized =
            analyze_github_quality("def f(flag)\n  value = \"x\" if flag\n  value.length\nend\n");
        assert!(
            uninitialized
                .iter()
                .any(|issue| issue.rule_key == "rb/uninitialized-local-variable")
        );
        assert!(
            analyze_github_quality("def f(flag)\n  value = \"x\" if flag\n  value.to_s\nend\n")
                .iter()
                .all(|issue| issue.rule_key != "rb/uninitialized-local-variable")
        );

        let query = analyze_github_quality(
            "class User < ApplicationRecord; end\nitems.each { User.find(1) }\n",
        );
        assert!(
            query
                .iter()
                .any(|issue| issue.rule_key == "rb/database-query-in-loop")
        );
        assert_eq!(
            query,
            analyze_github_quality(
                "class User < ApplicationRecord; end\nitems.each { User.find(1) }\n"
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

    #[test]
    fn s1192_reports_duplicated_literal_with_reference_message_and_flows() {
        let source = "def sample\n  [\n    \"dir/abc.rb\", \"dir/abc.rb\", \"dir/abc.rb\",\n\
                      \x20    \"dir/abc.rb\", \"dir/abc.rb\", \"dir/abc.rb\",\n\
                      \x20    \"dir/abc.rb\", \"dir/abc.rb\", \"dir/abc.rb\",\n  ]\nend\n";
        let report = analyze(
            PathBuf::from("test/test_rake_path_map.rb"),
            source,
            &AnalyzerOptions::default(),
        );
        let findings: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "ruby:S1192")
            .collect();
        assert_eq!(
            findings.len(),
            1,
            "exactly one finding for one repeated value"
        );
        let finding = findings[0];
        assert_eq!(
            finding.message,
            "Define a constant instead of duplicating this literal \"dir/abc.rb\" 9 times."
        );
        // The first occurrence anchors the finding: line 3, columns 4..16
        // (one-based line, zero-based half-open columns), quotes included.
        assert_eq!(finding.range.start.line, 3);
        assert_eq!(finding.range.start.column, 4);
        assert_eq!(finding.range.end.line, 3);
        assert_eq!(finding.range.end.column, 16);
        assert_eq!(finding.flows.len(), 1, "one secondary-location group");
        let locations = &finding.flows[0].locations;
        assert_eq!(locations.len(), 8, "every later occurrence is a flow");
        assert_eq!(locations[0].message, "Duplication");
        assert_eq!(locations[0].range.start.line, 3);
        assert_eq!(locations[0].range.start.column, 18);
    }

    #[test]
    fn s1192_keeps_reference_silent_controls_silent() {
        let source = "\
def controls(value)
  a = [\"ab.cd\", \"ab.cd\"]            # below threshold
  b = [\"ab.cd\", \"ab.cd\", \"ab.cd\"]  # five characters: below the floor
  c = [\"abcdef\", \"abcdef\", \"abcdef\"] # word characters only
  d = [\"word_char\", \"word_char\", \"word_char\"]
  e = [\"interp #{value}\", \"interp #{value}\", \"interp #{value}\"]
  f = %w[g-one-xy g-one-xy]             # below threshold
  g = \"ch\" \"ained-x\"
  h = \"ch\" \"ained-x\"
  i = \"ch\" \"ained-x\"
  j = <<~HERED
    hered-line-uniq
    hered-line-uniq
    hered-line-uniq
  HERED
  [a, b, c, d, e, f, g, h, i, j]
end
";
        let report = analyze(
            PathBuf::from("lib/controls.rb"),
            source,
            &AnalyzerOptions::default(),
        );
        assert!(
            report
                .issues
                .iter()
                .all(|issue| issue.rule_key != "ruby:S1192"),
            "no control may report: {:?}",
            report.issues
        );
    }

    #[test]
    fn s1192_groups_quoted_word_regex_and_shell_forms_by_value() {
        let source = "\
def merged
  %w[mq-two-x]
  [\"mq-two-x\", \"mq-two-x\"]
end

def probed
  [ /re-gex-one/, /re-gex-one/, /re-gex-one/ ]
  [ `shell-one-x`, `shell-one-x`, `shell-one-x` ]
  [ %q{pcen-q-one}, %q{pcen-q-one}, %q{pcen-q-one} ]
end
";
        let report = analyze(
            PathBuf::from("lib/forms.rb"),
            source,
            &AnalyzerOptions::default(),
        );
        let findings: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "ruby:S1192")
            .collect();
        assert_eq!(findings.len(), 4, "one finding per distinct value");
        let first = &findings[0];
        assert_eq!(
            first.message,
            "Define a constant instead of duplicating this literal \"mq-two-x\" 3 times."
        );
        // The word form is the first occurrence in source order; its span
        // excludes the %w[...] brackets.
        assert_eq!(first.range.start.line, 2);
        assert_eq!(first.range.start.column, 5);
        assert_eq!(first.range.end.column, 13);
        // Regex and subshell spans cover the content between the delimiters.
        let regex = &findings[1];
        assert_eq!(regex.range.start.line, 7);
        assert_eq!(regex.range.start.column, 5);
        assert_eq!(regex.range.end.column, 15);
        let subshell = &findings[2];
        assert_eq!(subshell.range.start.line, 8);
        assert_eq!(subshell.range.start.column, 5);
        assert_eq!(subshell.range.end.column, 16);
        let percent_q = &findings[3];
        assert_eq!(percent_q.range.start.line, 9);
        assert_eq!(percent_q.range.end.column, 18);
    }

    #[test]
    fn s1192_honors_the_catalog_threshold_option() {
        let source = "def twice\n  [\"tw-ice-x\", \"tw-ice-x\"]\nend\n";
        let options = AnalyzerOptions {
            duplicate_string_threshold: 2,
            ..AnalyzerOptions::default()
        };
        let report = analyze(PathBuf::from("lib/twice.rb"), source, &options);
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.rule_key == "ruby:S1192"),
            "threshold 2 flags the pair"
        );
    }

    #[test]
    fn s1192_never_fabricates_findings_on_malformed_input() {
        let source = "def broken(\"dup-one-x\", \"dup-one-x\", \"dup-one-x\"\n";
        let report = analyze(
            PathBuf::from("broken.rb"),
            source,
            &AnalyzerOptions::default(),
        );
        assert!(
            report
                .issues
                .iter()
                .all(|issue| issue.rule_key != "ruby:S1192")
        );
    }
}
