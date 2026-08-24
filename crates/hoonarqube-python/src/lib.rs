//! Tolerant Python analyzer lowering starter-rule findings into `hoonarqube-ir`.
//!
//! The crate parses Python with the embedded Ruff parser and lowers its checks
//! into [`hoonarqube_ir::FileReport`]s. Severity and type always resolve through
//! the frozen `hoonarqube-catalog` catalog via [`hoonarqube_ir::Issue::rule_key`];
//! they are deliberately never duplicated here.

#[cfg(test)]
use crate::engine::rx::RxNode;
#[cfg(test)]
use crate::engine::rx::RxParser;
#[cfg(test)]
use crate::engine::rx::RxUnit;
#[cfg(test)]
use crate::engine::rx::decode_string_part;
#[cfg(test)]
use crate::engine::rx::parse_regex;
use crate::rules::assign_plus_minus::check_assign_plus_minus;
use crate::rules::call_usage::check_call_usage;
use crate::rules::check_naming_convention_battery;
use crate::rules::check_regex_battery;
use crate::rules::check_size_metric_battery;
use crate::rules::check_structural_battery;
use crate::rules::check_tier_a_battery;
use crate::rules::check_tier_a_battery_2;
use crate::rules::check_tier_b_battery;
use crate::rules::check_tier_c_security_battery;
use crate::rules::check_tier_c_semantic_battery;
use crate::rules::cleartext_protocols::check_cleartext_protocols;
use crate::rules::commented_code::check_commented_code;
use crate::rules::ends_with_newline::check_ends_with_newline;
use crate::rules::hardcoded_credentials::check_hardcoded_credentials;
use crate::rules::hardcoded_ips::check_hardcoded_ips;
use crate::rules::hardcoded_secrets::check_hardcoded_secrets;
use crate::rules::invalid_string_escapes::check_invalid_string_escapes;
use crate::rules::issue_tags::check_issue_tags;
use crate::rules::keyword_parentheses::check_keyword_parentheses;
use crate::rules::license_header::check_license_header;
use crate::rules::line_length::check_line_length;
use crate::rules::lowercase_long_suffix::check_lowercase_long_suffix;
use crate::rules::mixed_string_concatenation::check_mixed_string_concatenation;
use crate::rules::module_name::check_module_name;
use crate::rules::no_sonar::check_no_sonar;
use crate::rules::noqa_comments::check_noqa_comments;
use crate::rules::one_statement_per_line::check_one_statement_per_line;
use crate::rules::parsing_errors::check_parsing_errors;
use crate::rules::pre_increment_decrement::check_pre_increment_decrement;
use crate::rules::py2_backticks::check_py2_backticks;
use crate::rules::py2_inequality::check_py2_inequality;
use crate::rules::trailing_whitespace::check_trailing_whitespace;
use crate::support::file_metrics;
use crate::support::parse;
use crate::support::sort_issues;
use ruff_source_file::LineIndex;
use std::path::PathBuf;

/// Knobs for the Python analyzer; defaults mirror the frozen catalog
/// `ParameterFact` defaults (`maximumLineLength` default `120`,
/// `maximumLinesOfCode` default `1000`, `maximumFunctionParameters` default
/// `13`, `maximumReturnStatements` default `3`, `maximumFunctionLength`
/// default `100`, `maximumNestingDepth` default `4`,
/// `maximumCognitiveComplexity` default `15`, complexity defaults
/// `200`/`200`/`15`,
/// S1192 duplicate-literal threshold `3`, S139 trailing-comment whitelist,
/// S1481 unused-local ignore pattern, S4487 single-underscore opt-in,
/// S5843 maximum regular-expression complexity `20`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzerOptions {
    pub maximum_line_length: u32,
    pub maximum_lines_of_code: u32,
    pub maximum_function_parameters: u32,
    pub maximum_return_statements: u32,
    pub maximum_function_length: u32,
    pub maximum_nesting_depth: u32,
    pub maximum_cognitive_complexity: u32,
    pub maximum_class_complexity: u32,
    pub maximum_file_complexity: u32,
    pub maximum_function_complexity: u32,
    /// Expected license/copyright header; empty disables the check,
    /// matching the `SonarQube` default where `headerFormat` is unset.
    /// Compared as a literal prefix after an optional shebang line.
    pub copyright_header_format: String,
    /// Occurrence count at which a string literal counts as duplicated
    /// (`python:S1192` catalog default `3`).
    pub duplicate_literal_threshold: u32,
    /// Exclusion pattern for `python:S1192`; empty disables exclusions.
    /// Matched as a plain substring when free of regex metacharacters.
    pub duplicate_literal_exclusion_regex: String,
    /// Trailing-comment whitelist shape for `python:S139`; empty selects the
    /// catalog default semantics (`fmt:`/`type:`/`noqa:` directives and
    /// single-token comments).
    pub legal_trailing_comment_pattern: String,
    /// Enables `python:S6538`/`python:S6540`. Off by default: the frozen
    /// catalog defines no parameters for these rules and unannotated legacy
    /// code would flood every analysis with findings.
    pub require_type_hints: bool,
    /// Ignore shape for `python:S1481` unused locals; matches the catalog
    /// `regex` default `(_[a-zA-Z0-9_]*|dummy|unused|ignored)` semantics:
    /// underscore-prefixed names plus the literal alternatives. Custom
    /// patterns are honored per top-level `|` alternation, supporting
    /// trailing `*` prefix wildcards and literal names.
    pub unused_local_ignore_pattern: String,
    /// Extends `python:S4487` to single-underscore attributes; mirrors the
    /// catalog `enableSingleUnderscoreIssues` parameter (default `false`).
    pub enable_single_underscore_attribute_issues: bool,
    /// Maximum complexity for `python:S5843` over parsed regular-expression
    /// patterns; mirrors the catalog `maxComplexity` parameter (default `20`).
    pub regex_maximum_complexity: u32,
}

impl Default for AnalyzerOptions {
    fn default() -> Self {
        Self {
            maximum_line_length: 120,
            maximum_lines_of_code: 1000,
            maximum_function_parameters: 13,
            maximum_return_statements: 3,
            maximum_function_length: 100,
            maximum_nesting_depth: 4,
            maximum_cognitive_complexity: 15,
            maximum_class_complexity: 200,
            maximum_file_complexity: 200,
            maximum_function_complexity: 15,
            copyright_header_format: String::new(),
            duplicate_literal_threshold: 3,
            duplicate_literal_exclusion_regex: String::new(),
            legal_trailing_comment_pattern: String::new(),
            require_type_hints: false,
            unused_local_ignore_pattern: String::from("(_[a-zA-Z0-9_]*|dummy|unused|ignored)"),
            enable_single_underscore_attribute_issues: false,
            regex_maximum_complexity: 20,
        }
    }
}

#[must_use]
pub fn analyze(
    path: PathBuf,
    source: &str,
    options: &AnalyzerOptions,
) -> hoonarqube_ir::FileReport {
    let parsed = parse(source);
    let index = LineIndex::from_source_text(source);
    let metrics = file_metrics(&parsed, source, &index);

    let mut issues = Vec::new();
    issues.extend(check_parsing_errors(&parsed, &index, source));
    issues.extend(check_no_sonar(&parsed, &index, source));
    issues.extend(check_line_length(source, options));
    issues.extend(check_ends_with_newline(source));
    issues.extend(check_trailing_whitespace(source));
    issues.extend(check_issue_tags(&parsed, &index, source));
    issues.extend(check_noqa_comments(&parsed, &index, source));
    issues.extend(check_license_header(options, source));
    issues.extend(check_module_name(path.as_path(), &index, source));
    issues.extend(check_hardcoded_ips(&parsed, &index, source));
    issues.extend(check_cleartext_protocols(&parsed, &index, source));
    issues.extend(check_hardcoded_credentials(&parsed, &index, source));
    issues.extend(check_hardcoded_secrets(&parsed, &index, source));
    issues.extend(check_commented_code(&parsed, &index, source));
    issues.extend(check_py2_backticks(&parsed, &index, source));
    issues.extend(check_py2_inequality(&parsed, &index, source));
    issues.extend(check_lowercase_long_suffix(&parsed, &index, source));
    issues.extend(check_pre_increment_decrement(&parsed, &index, source));
    issues.extend(check_assign_plus_minus(&parsed, &index, source));
    issues.extend(check_invalid_string_escapes(&parsed, &index, source));
    issues.extend(check_keyword_parentheses(&parsed, &index, source));
    issues.extend(check_mixed_string_concatenation(&parsed, &index, source));
    issues.extend(check_call_usage(
        &parsed,
        &index,
        source,
        "exec",
        "python:ExecStatementUsage",
        "Remove this usage of 'exec'.",
    ));
    issues.extend(check_call_usage(
        &parsed,
        &index,
        source,
        "print",
        "python:PrintStatementUsage",
        "Remove this usage of 'print'.",
    ));
    issues.extend(check_one_statement_per_line(&parsed, &index, source));
    issues.extend(check_tier_a_battery(&parsed, &index, source));
    issues.extend(check_tier_a_battery_2(&parsed, &index, source, options));
    issues.extend(check_naming_convention_battery(&parsed, &index, source));
    issues.extend(check_size_metric_battery(
        &parsed, &index, source, options, &metrics,
    ));
    issues.extend(check_tier_b_battery(&parsed, &index, source, options));
    issues.extend(check_regex_battery(&parsed, &index, source, options));
    issues.extend(check_tier_c_security_battery(&parsed, &index, source));
    issues.extend(check_tier_c_semantic_battery(&parsed, &index, source));
    issues.extend(check_structural_battery(&parsed, &index, source, options));
    sort_issues(&mut issues);

    hoonarqube_ir::FileReport {
        path,
        language: "python".to_string(),
        issues,
        metrics,
    }
}

pub(crate) mod context;
pub(crate) mod engine;
pub(crate) mod rules;
pub(crate) mod support;

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod tests;
