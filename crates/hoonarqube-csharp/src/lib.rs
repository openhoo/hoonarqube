//! Tolerant C# analyzer lowering starter-rule findings into `hoonarqube-ir`.
//!
//! The crate parses C# with tree-sitter (always produces a concrete syntax
//! tree, even for broken input) and lowers its checks into
//! [`hoonarqube_ir::FileReport`]s. Rule keys use the repository prefix of the
//! catalog (`csharpsquid:S103`); severity and type always resolve through the
//! frozen `hoonarqube-catalog` catalog via [`hoonarqube_ir::Issue::rule_key`],
//! never duplicated here. Syntax errors emit no issues (no catalog-backed
//! `ParsingError` rule exists for C#).
//!
//! # Documented coverage gaps (INFRA skips)
//!
//! Seven rules of the frozen `csharpsquid` catalog are intentionally not
//! implemented because the analysis infrastructure they require does not
//! exist in this crate; the coverage audit gaps are explained here in code:
//!
//! - `csharpsquid:S110`, `csharpsquid:S1200`, `csharpsquid:S1944`,
//!   `csharpsquid:S3242`, `csharpsquid:S3246`, `csharpsquid:S4047`
//!   (type-lattice and inheritance-coupling checks): detection needs
//!   Roslyn-grade type lattice / inheritance coupling graphs that a
//!   single-pass tree-sitter syntax tree cannot provide.
//! - `csharpsquid:S6802` (Razor component surface): `.razor` files are not
//!   ingested by this analyzer.

use std::path::PathBuf;

use tree_sitter::Parser;

/// Knobs for the C# analyzer; defaults mirror the frozen catalog
/// `ParameterFact` defaults (`maximumLineLength` default `200` for
/// `csharpsquid:S103`, `maximumFileLocThreshold` default `1000` for
/// `csharpsquid:S104`, the naming formats of `csharpsquid:S2342` and
/// `csharpsquid:S6669`, the `csharpsquid:S1451` header knobs, and the
/// `csharpsquid:S2436` generic-parameter caps `max`/`maxMethod`).
///
/// `header_format` intentionally defaults to empty (rule disabled) instead of
/// the sample template shipped in the catalog, so a default-configured
/// analyzer does not flag every file.
/// The Tier-A structural thresholds (`S107`, `S1151`, `S134`, `S138`,
/// `S1479`, `S1541`, `S1067`, `S3776`) mirror their catalog parameter
/// defaults, as do the Tier-A9 literal-scan knobs (`S1192` duplication
/// threshold, `S2068` credential words, `S6418` secret words and entropy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzerOptions {
    pub maximum_line_length: u32,
    /// `csharpsquid:S104` `maximumFileLocThreshold`.
    pub maximum_file_loc_threshold: u32,
    /// `csharpsquid:S1451` `headerFormat`; empty disables the header check.
    pub header_format: String,
    /// `csharpsquid:S1451` `isRegularExpression`. Regular-expression headers
    /// are not evaluated because this analyzer carries no regex engine.
    pub header_is_regular_expression: bool,
    /// `csharpsquid:S2342` `format` (enums without `[Flags]`).
    pub enum_naming_format: String,
    /// `csharpsquid:S2342` `flagsAttributeFormat` (enums with `[Flags]`).
    pub flags_enum_naming_format: String,
    /// `csharpsquid:S6669` logger-name `format`.
    pub logger_name_format: String,
    /// `csharpsquid:S2436` `max`: tolerated type parameters per type.
    pub maximum_generic_parameters_for_types: u32,
    /// `csharpsquid:S2436` `maxMethod`: tolerated type parameters per method.
    pub maximum_generic_parameters_for_methods: u32,
    /// `csharpsquid:S1479` tolerated statements per switch section.
    pub maximum_switch_section_statements: u32,
    /// `csharpsquid:S1151` tolerated lines per switch section.
    pub maximum_switch_section_lines: u32,
    /// `csharpsquid:S134` tolerated control-flow nesting depth.
    pub maximum_nesting_level: u32,
    /// `csharpsquid:S138` tolerated lines per function body.
    pub maximum_function_lines: u32,
    /// `csharpsquid:S107` tolerated parameters per method.
    pub maximum_method_parameters: u32,
    /// `csharpsquid:S1541` cyclomatic complexity threshold.
    pub maximum_function_complexity_threshold: u32,
    /// `csharpsquid:S3776` cognitive complexity threshold for callables.
    pub maximum_cognitive_complexity_threshold: u32,
    /// `csharpsquid:S3776` `propertyThreshold` for accessors.
    pub maximum_accessor_complexity_threshold: u32,
    /// `csharpsquid:S1067` tolerated logical operators per expression.
    pub maximum_logical_operators: u32,
    /// `csharpsquid:S1192` `threshold`: occurrences at which a repeated
    /// string literal is reported.
    pub duplicate_string_threshold: u32,
    /// `csharpsquid:S2068` `credentialWords`; entries match assigned names
    /// case-insensitively as substrings.
    pub credential_words: Vec<String>,
    /// `csharpsquid:S6418` `secretWords`. The catalog default entries are
    /// understood natively; custom entries degrade to substring matches.
    pub secret_words: Vec<String>,
    /// `csharpsquid:S6418` `randomnessSensibility`: distinct character
    /// classes required inside a suspected secret literal.
    pub secret_randomness_sensibility: u32,
}

impl Default for AnalyzerOptions {
    fn default() -> Self {
        Self {
            maximum_line_length: 200,
            maximum_file_loc_threshold: 1000,
            header_format: String::new(),
            header_is_regular_expression: false,
            enum_naming_format: "^([A-Z]{1,3}[a-z0-9]+)*([A-Z]{2})?$".to_string(),
            flags_enum_naming_format: "^([A-Z]{1,3}[a-z0-9]+)*([A-Z]{2})?s$".to_string(),
            logger_name_format: "^_?[Ll]og(ger)?$".to_string(),
            maximum_generic_parameters_for_types: 2,
            maximum_generic_parameters_for_methods: 3,
            maximum_switch_section_statements: 30,
            maximum_switch_section_lines: 8,
            maximum_nesting_level: 3,
            maximum_function_lines: 80,
            maximum_method_parameters: 7,
            maximum_function_complexity_threshold: 10,
            maximum_cognitive_complexity_threshold: 15,
            maximum_accessor_complexity_threshold: 3,
            maximum_logical_operators: 3,
            duplicate_string_threshold: 3,
            credential_words: vec![
                "password".to_string(),
                "passwd".to_string(),
                "pwd".to_string(),
                "passphrase".to_string(),
            ],
            secret_words: vec![
                r"api[_\-]?key".to_string(),
                "auth".to_string(),
                "credential".to_string(),
                "secret".to_string(),
                "token".to_string(),
            ],
            secret_randomness_sensibility: 3,
        }
    }
}

/// Language marker; one variant today, keeps call sites future-proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsLanguage {
    CSharp,
}

impl CsLanguage {
    /// Repository prefix used in issue `rule_key`s (`csharpsquid:S103`).
    #[must_use]
    pub fn prefix(self) -> &'static str {
        "csharpsquid"
    }
}

/// Analyzes one C# source file and lowers every rule finding into a
/// [`hoonarqube_ir::FileReport`] with sorted issues and file metrics.
#[must_use]
pub fn analyze(
    path: PathBuf,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> hoonarqube_ir::FileReport {
    let tree = parse(source);
    let root = tree.root_node();
    let mut issues = Vec::new();
    issues.extend(rules::text_scans::text_issues(
        root, source, language, options,
    ));
    issues.extend(rules::naming::naming_issues(
        root, source, language, options,
    ));
    issues.extend(rules::modifiers::modifier_issues(
        root, source, language, options,
    ));
    issues.extend(rules::structure::structure_issues(
        root, source, language, options,
    ));
    issues.extend(rules::expressions::expression_issues(
        root, source, language,
    ));
    issues.extend(rules::declaration_contracts::contract_issues(
        root, source, language,
    ));
    issues.extend(rules::literals::literal_content_issues(
        root, source, language, options,
    ));
    issues.extend(rules::usage::usage_heuristic_issues(root, source, language));
    issues.extend(rules::type_members::declaration_contract_issues(
        root, source, language,
    ));
    issues.extend(rules::security::security_deny_list_issues(
        root, source, language,
    ));
    issues.extend(rules::datetime_aspnet::datetime_aspnet_issues(
        root, source, language,
    ));
    issues.extend(rules::logging::logging_issues(
        root, source, language, options,
    ));
    issues.extend(rules::linq_api::linq_api_issues(root, source, language));
    issues.extend(rules::usage_analysis::usage_analysis_issues(
        root, source, language,
    ));
    issues.extend(rules::dataflow::dataflow_cfg_issues(root, source, language));
    issues.extend(rules::api_patterns::framework_api_issues(
        root, source, language,
    ));
    issues.extend(rules::tier_c::tier_c_heuristic_issues(
        root, source, language,
    ));
    hoonarqube_ir::sort_issues(&mut issues);

    hoonarqube_ir::FileReport {
        path,
        language: language.prefix().to_string(),
        issues,
        metrics: metrics::file_metrics(tree.root_node(), source),
    }
}

fn parse(source: &str) -> tree_sitter::Tree {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
        .expect("tree-sitter-c-sharp grammar is compatible");
    parser
        .parse(source, None)
        .expect("parse always yields a tree")
}

mod cst;
mod metrics;
mod rules;
mod symbol_table;

#[cfg(test)]
mod tests;
