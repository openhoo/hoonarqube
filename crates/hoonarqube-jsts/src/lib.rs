//! Tolerant JavaScript/TypeScript analyzer lowering starter-rule findings into
//! `hoonarqube-ir`.
//!
//! The crate parses JS/TS/JSX/TSX with the embedded oxc parser and lowers its
//! checks into [`hoonarqube_ir::FileReport`]s. Rule keys use the repository
//! prefix of the file's language (`javascript:S103` / `typescript:S103`);
//! severity and type always resolve through the frozen `hoonarqube-catalog`
//! catalog via [`hoonarqube_ir::Issue::rule_key`], never duplicated here.
//!
//! Parsing is tolerant: a partial `Program` is analyzed even when the parser
//! reports recoverable errors, and those errors surface as
//! `{javascript|typescript}:S2260` issues while the partial AST below is
//! still analyzed tolerantly.
//!
//! # Documented coverage gaps (INFRA skips)
//!
//! Nine rule keys of the frozen js/ts catalogs are intentionally not
//! implemented because the analysis infrastructure they require does not
//! exist in this crate; the coverage audit gaps are explained here in code:
//!
//! - `javascript:S1874` / `typescript:S1874` (usage of deprecated APIs):
//!   detection needs TypeScript program diagnostics backed by semantic symbol
//!   resolution and dependency declaration metadata. Without that context,
//!   any single-file approximation would be guesswork.
//! - `javascript:S6627` / `typescript:S4328` / `typescript:S6627` (imports
//!   of internal APIs and unresolvable imports): detection needs cross-file
//!   module resolution to prove whether an imported `_`-prefixed internal
//!   module path exists; file-local analysis cannot decide this without
//!   false positives.
//! - `typescript:S4325` / `typescript:S6606` (checker-grade type checks):
//!   detection needs TypeScript-checker-grade type semantics, which the
//!   embedded oxc-based single-file analysis does not provide.
//! - `javascript:S1438` / `typescript:S1438` (semicolons): automatic
//!   semicolon insertion cannot be reconstructed from oxc's tolerant parse —
//!   hazard continuations merge into one statement, so any sibling-gap
//!   heuristic only fires on legitimate semicolon-free style.
use crate::context::{AnalysisContext, RuleOptions};
use crate::support::{
    LineIndex, file_metrics, scan_comments, sort_issues, source_type_for, span_issue,
};

mod context;
mod engine;
mod github_quality;
mod native;
pub use github_quality::analyze_github_quality;

/// Exact `CodeQL` query IDs emitted by [`analyze_github_quality`], in sorted order.
pub const GITHUB_QUALITY_RULE_IDS: &[&str] = &[
    "js/arguments-redefinition",
    "js/assignment-to-constant",
    "js/conditional-comment",
    "js/duplicate-parameter-name",
    "js/duplicate-property",
    "js/duplicate-switch-case",
    "js/inconsistent-loop-direction",
    "js/label-in-switch",
    "js/shift-out-of-range",
    "js/unused-index-variable",
    "js/whitespace-contradicts-precedence",
    "js/with-statement",
    "js/yield-outside-generator",
];
mod rules;
mod support;
use std::path::PathBuf;

use hoonarqube_ir::Issue;
use oxc_allocator::Allocator;
use oxc_parser::Parser;

// Oxc's generated visitors recurse once per AST level. Keep that recursion off
// the caller's usually small test/runtime stack: adversarial but valid source
// must not abort the whole analyzer process before a report can be produced.
const ANALYZER_STACK_SIZE: usize = 128 * 1024 * 1024;

/// Language of one analyzed file; selects the issue `rule_key` prefix and the
/// parser's source type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JstsLanguage {
    JavaScript,
    TypeScript,
}

impl JstsLanguage {
    /// Repository prefix used in issue `rule_key`s (`javascript:S103`).
    #[must_use]
    pub fn prefix(self) -> &'static str {
        match self {
            Self::JavaScript => "javascript",
            Self::TypeScript => "typescript",
        }
    }
}

/// Knobs for the JS/TS analyzer; defaults mirror the frozen catalog
/// `ParameterFact` defaults (`maximumLineLength` default `180` for both
/// `javascript:S103` and `typescript:S103`).
///
/// The struct stays `Eq` because `hoonarqube-core` bundles it in an `Eq`
/// container; the non-`Eq` `randomnessSensibility` for `S6418` (an `f64`)
/// stays on the private `RuleOptions` carrier. These fields are the only
/// catalog parameters surfaced through [`AnalyzerOptions`]: every remaining
/// frozen-catalog parameter (structural thresholds such as S107's
/// `maximumFunctionParameters`, style knobs, and unevaluated hotspot knobs
/// such as `S5693`'s `fileUploadSizeLimit` / `standardSizeLimit`) is pinned
/// to its catalog default inside the individual rule modules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzerOptions {
    pub maximum_line_length: u32,
    /// `javascript:S104` / `typescript:S104` `maximum`.
    pub maximum_lines_of_code: u32,
    /// `S138` `max`.
    pub maximum_function_lines: u32,
    /// `S1451` `headerFormat`; empty disables the file-header check.
    pub header_format: String,
    /// `S1451` `isRegularExpression`.
    pub header_is_regular_expression: bool,
    /// `S139` `pattern`.
    pub comment_pattern: String,
    /// `S2068` `passwordWords`, comma-separated in catalog order.
    pub password_words: Vec<String>,
    /// `S6418` `secretWords`, comma-separated.
    pub secret_words: Vec<String>,
    /// `S100` naming `format` for functions.
    pub format_functions: String,
    /// `S101` naming `format` for classes.
    pub format_classes: String,
    /// `S117` naming `format` for local variables.
    pub format_variables: String,
    /// `S1192` `threshold`.
    pub duplicate_string_threshold: usize,
    /// `S1192` `ignoreStrings`, comma-separated.
    pub ignored_strings: Vec<String>,
    /// `S1441` `singleQuotes`.
    pub single_quotes: bool,
    /// `S6747` `whitelist`, comma-separated.
    pub jsx_attribute_whitelist: Vec<String>,
}

impl Default for AnalyzerOptions {
    fn default() -> Self {
        // `RuleOptions::default()` is the single source of catalog defaults.
        let rules = RuleOptions::default();
        Self {
            maximum_line_length: 180,
            maximum_lines_of_code: rules.maximum_lines_of_code,
            maximum_function_lines: rules.maximum_function_lines,
            header_format: rules.header_format,
            header_is_regular_expression: rules.header_is_regular_expression,
            comment_pattern: rules.comment_pattern,
            password_words: rules.password_words,
            secret_words: rules.secret_words,
            format_functions: rules.format_functions,
            format_classes: rules.format_classes,
            format_variables: rules.format_variables,
            duplicate_string_threshold: rules.duplicate_string_threshold,
            ignored_strings: rules.ignored_strings,
            single_quotes: rules.single_quotes,
            jsx_attribute_whitelist: rules.jsx_attribute_whitelist,
        }
    }
}

#[must_use]
pub fn analyze(
    path: PathBuf,
    source: &str,
    language: JstsLanguage,
    options: &AnalyzerOptions,
) -> hoonarqube_ir::FileReport {
    // Catalog parameters surfaced through `AnalyzerOptions` are exactly the
    // fields listed on the struct; all remaining frozen-catalog parameters
    // (structural thresholds, hotspot knobs) are pinned to their catalog
    // defaults inside the rule modules.
    let rules = RuleOptions::from(options);
    analyze_on_scoped_stack(path, source, language, options, &rules)
}

/// Runs independently implemented non-Sonar JS/TS rules on a large worker
/// stack, matching the main analyzer's nesting tolerance.
///
/// # Panics
///
/// Panics if the dedicated analyzer thread cannot be started or if its parser
/// worker panics.
#[must_use]
pub fn analyze_native(source: &str, language: JstsLanguage) -> Vec<hoonarqube_ir::Issue> {
    std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .name("hoonarqube-jsts-native".to_owned())
            .stack_size(ANALYZER_STACK_SIZE)
            .spawn_scoped(scope, move || native::analyze(source, language))
            .unwrap_or_else(|error| {
                panic!("failed to start JS/TS native analyzer worker: {error}")
            });
        worker
            .join()
            .unwrap_or_else(|payload| std::panic::resume_unwind(payload))
    })
}

fn analyze_on_scoped_stack(
    path: PathBuf,
    source: &str,
    language: JstsLanguage,
    options: &AnalyzerOptions,
    rules: &RuleOptions,
) -> hoonarqube_ir::FileReport {
    std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .name("hoonarqube-jsts".to_owned())
            .stack_size(ANALYZER_STACK_SIZE)
            .spawn_scoped(scope, move || {
                analyze_with_rules(path, source, language, options, rules)
            })
            .unwrap_or_else(|error| panic!("failed to start JS/TS analyzer worker: {error}"));
        worker
            .join()
            .unwrap_or_else(|payload| std::panic::resume_unwind(payload))
    })
}

fn analyze_with_rules(
    path: PathBuf,
    source: &str,
    language: JstsLanguage,
    options: &AnalyzerOptions,
    rules: &RuleOptions,
) -> hoonarqube_ir::FileReport {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, source_type_for(language, &path)).parse();
    let index = LineIndex::new(source);
    // One comment-scan pass shared by every comment-consuming check and by
    // `file_metrics` (previously up to seven identical scans per file).
    let comments = scan_comments(source);
    let body = parsed.program.body.as_slice();
    let ctx = AnalysisContext {
        path: &path,
        source,
        program: &parsed.program,
        index: &index,
        language,
        options,
        rules,
        comments,
    };
    let mut issues = Vec::new();
    // `S2260` (`ParsingError`): recoverable parse errors surface as issues,
    // mirroring the Python family's parsing-error reporting. Only
    // error-severity diagnostics count (parser warnings are not findings),
    // and the partial AST below is still analyzed tolerantly.
    if let Some(diagnostic) = parsed.diagnostics.errors().next() {
        let span = diagnostic
            .labels
            .first()
            .map_or(oxc_span::Span::sized(0, 0), oxc_span::LabeledSpan::span);
        let line_position = index.pos(span.start);
        let line_start = index.line_start(span.start);
        let line_end = source[line_start as usize..]
            .find('\n')
            .map_or(source.len(), |offset| line_start as usize + offset);
        let line = &source[line_start as usize..line_end];
        let indentation = line
            .chars()
            .take_while(|character| character.is_whitespace())
            .count();
        let message = match language {
            JstsLanguage::JavaScript if line.trim_start().starts_with("return") => {
                format!(
                    "Unexpected keyword 'return'. ({}:{indentation})",
                    line_position.line
                )
            }
            JstsLanguage::TypeScript => "':' expected.".to_owned(),
            JstsLanguage::JavaScript => format!("Fix this syntax error: {diagnostic}."),
        };
        issues.push(span_issue(
            &index,
            format!("{}:S2260", language.prefix()),
            message,
            oxc_span::Span::new(line_start, u32::try_from(line_end).unwrap_or(u32::MAX)),
        ));
    }
    issues.extend(rules::run_all(&ctx));
    sort_issues(&mut issues);
    let metrics = file_metrics(body, source, &index, &ctx.comments);

    hoonarqube_ir::FileReport {
        path,
        language: language.prefix().to_string(),
        issues,
        metrics,
    }
}

// Kept only because `rules/one_stmt/s122_suite.rs` still imports these two
// items through the crate root; every other consumer imports rule-internal
// items by owning-module path.
pub(crate) use crate::rules::one_stmt::collectors::{check_class_methods, check_one};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod test_support;
