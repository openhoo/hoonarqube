//! Tolerant Python analyzer lowering starter-rule findings into `hoonarqube-ir`.
//!
//! The crate parses Python with the embedded Ruff parser and lowers its checks
//! into [`hoonarqube_ir::FileReport`]s. Severity and type always resolve through
//! the frozen `hoonarqube-catalog` catalog via [`hoonarqube_ir::Issue::rule_key`];
//! they are deliberately never duplicated here.
//!
//! GraphQL introspection (`python:S6786`) uses the explicit
//! [`PythonProjectContext`] API for syntax-backed imports, aliases, re-exports,
//! and inheritance.  Dynamic or unresolved configuration remains a distinct
//! resolver state and is not guessed as safe.

use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;

use crate::engine::file_context::FileContext;
pub use crate::engine::project_context::PythonProjectContext;
use crate::engine::project_context::module_name_from_path;
#[cfg(test)]
use crate::engine::rx::RxUnit;
#[cfg(test)]
use crate::engine::rx::decode_string_part;
#[cfg(test)]
use crate::engine::rx::parse_regex;
use crate::quickfix::attach_quick_fixes;
use crate::rules::assign_plus_minus::check_assign_plus_minus;
use crate::rules::check_future_reference_battery;
use crate::rules::check_future_test_contract_battery;
use crate::rules::check_naming_convention_battery;
use crate::rules::check_pytest_contract_battery;
use crate::rules::check_regex_battery;
use crate::rules::check_size_metric_battery;
use crate::rules::check_structural_battery;
use crate::rules::check_test_assertion_battery;
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
use crate::rules::py2_statements::check_py2_statements;
use crate::rules::s6786_graphql_introspection::check_s6786_graphql_introspection;
use crate::rules::trailing_whitespace::check_trailing_whitespace;
/// Sonar rules from the frozen catalog that declare scope `MAIN`.
/// `SonarQube` never reports MAIN-scope rules on test sources, so these
/// findings are dropped for test-scoped files (conventional test directories,
/// `test*`/`conftest*`/`*_test.py` names, per the reference's test
/// detection). The remaining rules declare scope `ALL` (or `TEST`) and still
/// apply; documentation trees such as `docs/` stay MAIN scope because the
/// reference keeps reporting MAIN rules there.
const MAIN_SCOPE_RULE_KEYS: &[&str] = &[
    "python:BackticksUsage",
    "python:ClassComplexity",
    "python:ExecStatementUsage",
    "python:FileComplexity",
    "python:FunctionComplexity",
    "python:InequalityUsage",
    "python:LongIntegerWithLowercaseSuffixUsage",
    "python:PreIncrementDecrement",
    "python:PrintStatementUsage",
    "python:S1045",
    "python:S112",
    "python:S1131",
    "python:S1142",
    "python:S1192",
    "python:S1313",
    "python:S138",
    "python:S1515",
    "python:S1523",
    "python:S1542",
    "python:S1578",
    "python:S1707",
    "python:S1716",
    "python:S1717",
    "python:S1720",
    "python:S1721",
    "python:S1722",
    "python:S1763",
    "python:S1871",
    "python:S2053",
    "python:S2068",
    "python:S2077",
    "python:S2092",
    "python:S2115",
    "python:S2159",
    "python:S2201",
    "python:S2245",
    "python:S2257",
    "python:S2612",
    "python:S2638",
    "python:S2710",
    "python:S2711",
    "python:S2712",
    "python:S2733",
    "python:S2734",
    "python:S2737",
    "python:S2755",
    "python:S2772",
    "python:S2836",
    "python:S2876",
    "python:S3329",
    "python:S3330",
    "python:S3403",
    "python:S3516",
    "python:S3752",
    "python:S3801",
    "python:S4423",
    "python:S4426",
    "python:S4433",
    "python:S4502",
    "python:S4507",
    "python:S4721",
    "python:S4784",
    "python:S4787",
    "python:S4790",
    "python:S4792",
    "python:S4823",
    "python:S4828",
    "python:S4829",
    "python:S4830",
    "python:S5042",
    "python:S5122",
    "python:S5247",
    "python:S5300",
    "python:S5332",
    "python:S5344",
    "python:S5439",
    "python:S5443",
    "python:S5445",
    "python:S5527",
    "python:S5542",
    "python:S5547",
    "python:S5549",
    "python:S5659",
    "python:S5717",
    "python:S5754",
    "python:S5806",
    "python:S5807",
    "python:S5996",
    "python:S6245",
    "python:S6252",
    "python:S6265",
    "python:S6270",
    "python:S6281",
    "python:S6302",
    "python:S6304",
    "python:S6321",
    "python:S6323",
    "python:S6326",
    "python:S6328",
    "python:S6329",
    "python:S6331",
    "python:S6333",
    "python:S6353",
    "python:S6377",
    "python:S6418",
    "python:S6437",
    "python:S6463",
    "python:S6725",
    "python:S905",
    "python:S9073",
    "python:S930",
];
use crate::support::file_metrics;
use crate::support::is_test_scope_file;
use crate::support::parse;
use crate::support::sort_issues;
use ruff_source_file::LineIndex;
use std::path::PathBuf;

mod native;

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
// A parameter bag mirroring catalog rule parameters; several rules expose a
// boolean knob, so the struct legitimately accumulates them.
#[allow(clippy::struct_excessive_bools)]
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
    /// Enables `python:S6540`. Off by default: the frozen catalog defines no
    /// parameters for the rule and unannotated legacy code would flood every
    /// analysis with findings. `python:S6538` is catalog-active and always
    /// runs; its test-scope gate mirrors the reference analyzer's
    /// production-only execution instead of this knob.
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
    /// Reports `python:S905` findings for no-effect string statements;
    /// mirrors the catalog `reportOnStrings` parameter (default `false`),
    /// so docstrings and attribute documentation strings stay clean.
    pub report_on_strings: bool,
    /// Maximum complexity for `python:S5843` over parsed regular-expression
    /// patterns; mirrors the catalog `maxComplexity` parameter (default `20`).
    pub regex_maximum_complexity: u32,
    /// Requires empty parentheses on argument-free `pytest.fixture` /
    /// `pytest.mark.*` decorators for `python:S9083`; mirrors the catalog
    /// `requireParentheses` parameter (default `false`, which flags the
    /// empty-parentheses style instead).
    pub require_pytest_decorator_parentheses: bool,
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
            report_on_strings: false,
            regex_maximum_complexity: 20,
            require_pytest_decorator_parentheses: false,
        }
    }
}
#[must_use]
pub fn analyze(
    path: PathBuf,
    source: &str,
    options: &AnalyzerOptions,
) -> hoonarqube_ir::FileReport {
    analyze_with_context(path, source, options, &PythonProjectContext::new())
}

/// Runs the Python analyzer with syntax-backed cross-module facts.
///
/// The context is explicit so the caller controls the project/module boundary;
/// unresolved imports and dynamic values remain unresolved instead of being
/// guessed from names.
#[must_use]
pub fn analyze_with_context(
    path: PathBuf,
    source: &str,
    options: &AnalyzerOptions,
    project: &PythonProjectContext,
) -> hoonarqube_ir::FileReport {
    let parsed = parse(source);
    let index = LineIndex::from_source_text(source);
    let metrics = file_metrics(&parsed, source, &index);
    let file_ctx = FileContext::build(&parsed);

    let mut issues = Vec::new();
    issues.extend(check_parsing_errors(&parsed, &index, source));
    issues.extend(check_no_sonar(&parsed, &index, source));
    issues.extend(check_line_length(source, options));
    issues.extend(check_ends_with_newline(path.as_path(), source));
    issues.extend(check_trailing_whitespace(source));
    issues.extend(check_issue_tags(&parsed, &index, source));
    issues.extend(check_noqa_comments(&parsed, &index, source));
    issues.extend(check_license_header(options, source));
    issues.extend(check_module_name(path.as_path(), &index, source));
    issues.extend(check_hardcoded_ips(&parsed, &index, source));
    issues.extend(check_cleartext_protocols(&parsed, &index, source));
    issues.extend(check_hardcoded_credentials(
        &parsed, &index, source, &file_ctx,
    ));
    issues.extend(check_hardcoded_secrets(&index, source, &file_ctx));
    issues.extend(check_commented_code(&parsed, &index, source));
    issues.extend(check_py2_backticks(&parsed, &index, source));
    issues.extend(check_py2_inequality(&parsed, &index, source));
    issues.extend(check_py2_statements(&parsed, &index, source));
    issues.extend(check_lowercase_long_suffix(&parsed, &index, source));
    issues.extend(check_pre_increment_decrement(&parsed, &index, source));
    issues.extend(check_assign_plus_minus(&parsed, &index, source));
    issues.extend(check_invalid_string_escapes(&index, source, &file_ctx));
    issues.extend(check_mixed_string_concatenation(&parsed, &index, source));
    issues.extend(check_one_statement_per_line(&parsed, &index, source));
    issues.extend(check_tier_a_battery(
        &parsed, &index, source, options, &file_ctx,
    ));
    issues.extend(check_tier_a_battery_2(
        &parsed, &index, source, options, &file_ctx,
    ));
    issues.extend(check_naming_convention_battery(
        &parsed, &index, source, &file_ctx,
    ));
    issues.extend(check_size_metric_battery(
        &parsed, &index, source, options, &metrics,
    ));
    issues.extend(check_tier_b_battery(
        &parsed,
        &index,
        source,
        options,
        &file_ctx,
        path.as_path(),
    ));
    issues.extend(check_regex_battery(&parsed, &index, source, options));
    let module_name = module_name_from_path(path.as_path());
    add_web_security_batteries(
        &parsed,
        &index,
        source,
        &file_ctx,
        &module_name,
        project,
        &mut issues,
    );
    issues.extend(check_test_assertion_battery(
        &parsed,
        &index,
        source,
        path.as_path(),
    ));
    issues.extend(check_pytest_contract_battery(
        &parsed,
        &index,
        source,
        path.as_path(),
    ));
    issues.extend(check_future_test_contract_battery(
        &parsed, &index, source, options,
    ));
    issues.extend(check_future_reference_battery(
        &parsed, &index, source, &file_ctx,
    ));
    issues.extend(check_structural_battery(
        path.as_path(), &parsed, &index, source, options, &file_ctx,
    ));
    if is_test_scope_file(path.as_path()) {
        issues.retain(|issue| !MAIN_SCOPE_RULE_KEYS.contains(&issue.rule_key.as_str()));
    }
    attach_quick_fixes(&parsed, &index, source, &file_ctx, &mut issues);
    sort_issues(&mut issues);

    hoonarqube_ir::FileReport {
        path,
        language: "python".to_string(),
        issues,
        metrics,
    }
}

/// Aggregates the Tier-C security, semantic, and GraphQL project-context
/// batteries that share the module provenance facts.
#[allow(clippy::too_many_arguments)]
fn add_web_security_batteries(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
    module_name: &str,
    project: &PythonProjectContext,
    issues: &mut Vec<Issue>,
) {
    issues.extend(check_tier_c_security_battery(
        parsed,
        index,
        source,
        file_ctx,
        module_name,
        project,
    ));
    issues.extend(check_tier_c_semantic_battery(
        parsed, index, source, file_ctx,
    ));
    issues.extend(check_s6786_graphql_introspection(
        parsed,
        index,
        source,
        file_ctx,
        module_name,
        project,
    ));
}

/// Runs independently implemented, non-Sonar Python rules. Profile selection
/// remains the caller's responsibility.
#[must_use]
pub fn analyze_native(source: &str) -> Vec<hoonarqube_ir::Issue> {
    native::analyze(source)
}
/// Exact `CodeQL` query IDs emitted by [`analyze_github_quality`], in sorted order.
pub const GITHUB_QUALITY_RULE_IDS: &[&str] = &[
    "py/explicit-call-to-delete",
    "py/file-not-closed",
    "py/implicit-string-concatenation-in-list",
    "py/redundant-global-declaration",
    "py/regex/backspace-escape",
    "py/str-format/mixed-fields",
];

/// Runs the independently implemented GitHub `CodeQL` Python quality queries.
///
/// This is a dedicated profile surface and does not alter Sonar/native output.
#[must_use]
pub fn analyze_github_quality(source: &str) -> Vec<hoonarqube_ir::Issue> {
    let issues = github_quality::analyze(source);
    debug_assert!(
        issues
            .iter()
            .all(|issue| GITHUB_QUALITY_RULE_IDS.contains(&issue.rule_key.as_str()))
    );
    issues
}

mod github_quality;

/// Runs GitHub Code Quality queries and computes file metrics from one parse.
#[must_use]
pub fn analyze_github_quality_report(path: PathBuf, source: &str) -> hoonarqube_ir::FileReport {
    let parsed = parse(source);
    let index = LineIndex::from_source_text(source);
    hoonarqube_ir::FileReport {
        path,
        language: "python".to_owned(),
        issues: github_quality::analyze_parsed(source, &parsed, &index),
        metrics: file_metrics(&parsed, source, &index),
    }
}

mod context;
mod engine;
pub(crate) mod quickfix;
mod rules;
mod support;

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod tests;
