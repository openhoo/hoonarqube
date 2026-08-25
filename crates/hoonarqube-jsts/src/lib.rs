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
//! reports recoverable errors, and parse errors themselves emit no issues (the
//! frozen js/ts catalogs contain no `ParsingError` rule).
//!
//! # Documented coverage gaps (INFRA skips)
//!
//! Two rules of the frozen js/ts catalogs are intentionally not implemented
//! because the analysis infrastructure they require does not exist in this
//! crate; the coverage audit gaps are explained here in code:
//!
//! - `javascript:S1874` / `typescript:S1874` (usage of deprecated APIs):
//!   detection needs a deprecated-API database (browser/ECMAScript
//!   compatibility dataset) that is not bundled with the analyzer. Without
//!   that data, any single-file approximation would be guesswork.
//! - `javascript:S6627` / `typescript:S6627` (imports of internal APIs):
//!   detection needs cross-file module resolution to prove whether the
//!   imported `_`-prefixed internal module path exists; file-local analysis
//!   cannot decide this without false positives.

// --- split:generated imports ---
use crate::context::{AnalysisContext, RuleOptions};
use crate::support::{LineIndex, extension_of, file_metrics, sort_issues, source_type_for};
// --- split:end imports ---
mod context;
mod engine;
mod rules;
mod support;
use std::path::PathBuf;

use hoonarqube_ir::Issue;
use oxc_allocator::Allocator;
use oxc_parser::Parser;

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

/// Maps a file extension to a language; `.js .jsx .mjs .cjs` map to
/// JavaScript, `.ts .tsx .mts .cts` to TypeScript, anything else to `None`.
#[must_use]
pub fn language_for_extension(ext: &str) -> Option<JstsLanguage> {
    match ext {
        "js" | "jsx" | "mjs" | "cjs" => Some(JstsLanguage::JavaScript),
        "ts" | "tsx" | "mts" | "cts" => Some(JstsLanguage::TypeScript),
        _ => None,
    }
}

/// Knobs for the JS/TS analyzer; defaults mirror the frozen catalog
/// `ParameterFact` defaults (`maximumLineLength` default `180` for both
/// `javascript:S103` and `typescript:S103`).
///
/// The public shape is deliberately stable (`hoonarqube-cli` constructs this
/// struct literally); the remaining catalog parameters live in the private
/// [`RuleOptions`] until the CLI bundle threads them through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzerOptions {
    pub maximum_line_length: u32,
}

impl Default for AnalyzerOptions {
    fn default() -> Self {
        Self {
            maximum_line_length: 180,
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
    // Catalog-backed rule parameters beyond `maximumLineLength` are not
    // threaded through the CLI bundle yet; the library defaults mirror the
    // frozen catalog values (see `RuleOptions`).
    let rules = RuleOptions::default();
    analyze_with_rules(path, source, language, options, &rules)
}

fn analyze_with_rules(
    path: PathBuf,
    source: &str,
    language: JstsLanguage,
    options: &AnalyzerOptions,
    rules: &RuleOptions,
) -> hoonarqube_ir::FileReport {
    let allocator = Allocator::default();
    let parsed = Parser::new(
        &allocator,
        source,
        source_type_for(language, extension_of(&path)),
    )
    .parse();
    let index = LineIndex::new(source);
    let body = parsed.program.body.as_slice();
    let ctx = AnalysisContext {
        path: &path,
        source,
        program: &parsed.program,
        index: &index,
        language,
        options,
        rules,
    };
    let mut issues = Vec::new();
    // `S2260` (`ParsingError`) hook: `parsed.errors` is deliberately not
    // reported — see the module documentation for the tolerant-parse
    // decision; the partial AST below is analyzed regardless.
    let _ = &parsed.diagnostics;
    issues.extend(rules::run_all(&ctx));
    sort_issues(&mut issues);

    hoonarqube_ir::FileReport {
        path,
        language: language.prefix().to_string(),
        issues,
        metrics: file_metrics(body, source, &index),
    }
}

pub(crate) use crate::rules::batch2d::collectors::{
    ClassAccessorCollector, DuplicationCollector, FunctionMetricsCollector,
    KeywordPlacementCollector, PromiseFlowCollector,
};
pub(crate) use crate::rules::batch5::collectors::{SecurityHotspotCollector, TsTypeCollector};
use crate::rules::batch5::collectors_hotspots::{
    MiscCollector, check_default_export_name, check_self_imports,
};
pub(crate) use crate::rules::expression::collectors::{
    check_collection_and_object_calls, check_logging_and_binding_calls,
};
pub(crate) use crate::rules::jsx_a11y::collectors::{
    IMPLICIT_ROLES, INTERACTIVE_ROLES, NON_INTERACTIVE_ROLES, jsx_has_attribute,
    language_tag_is_valid,
};
pub(crate) use crate::rules::one_stmt::collectors::{check_class_methods, check_one};
pub(crate) use crate::rules::react_jsx::collectors::{
    REACT_DOM_ATTRIBUTES, expression_returns_jsx,
};
pub(crate) use crate::rules::regex_family::collectors::{
    REGEX_COMPLEXITY_THRESHOLD, emit_concise_class_rewrite, emit_space_runs_in_sequence,
    flag_single_char_alternation, for_every_sequence, is_bare_control_character,
};
pub(crate) use crate::rules::shared::is_literal_expression;
pub(crate) use crate::rules::statement::collectors::is_error_type_name;
pub(crate) use crate::rules::tier_b::collectors::{
    ClassRuleCollector, TrailingCommaList, TrailingCommaListCollector,
};

#[cfg(test)]
use crate::rules::switch_flow::walker::MAX_SWITCH_CASES;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod test_support;
