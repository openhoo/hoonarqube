//! Tolerant C# analyzer lowering starter-rule findings into `hoonarqube-ir`.
//!
//! The crate parses C# with tree-sitter (always produces a concrete syntax
//! tree, even for broken input) and lowers its checks into
//! [`hoonarqube_ir::FileReport`]s. Rule keys use the repository prefix of the
//! catalog (`csharpsquid:S103`); severity and type always resolve through the
//! frozen `hoonarqube-catalog` catalog via [`hoonarqube_ir::Issue::rule_key`],
//! never duplicated here. Syntax errors emit no issues (no catalog-backed
//! `ParsingError` rule exists for C#).

use std::path::{Path, PathBuf};

use hoonarqube_ir::Issue;
use tree_sitter::{Node, Parser};

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

/// Maps a file extension to a language; `.cs` is C#, anything else is `None`.
#[must_use]
pub fn language_for_extension(ext: &str) -> Option<CsLanguage> {
    match ext {
        "cs" => Some(CsLanguage::CSharp),
        _ => None,
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
    issues.extend(check_line_length(source, language, options));
    issues.extend(check_file_loc(root, language, options));
    issues.extend(check_tabs(source, language));
    issues.extend(check_final_newline(source, language));
    issues.extend(check_header(source, language, options));
    issues.extend(check_close_brace_column(root, language));
    issues.extend(check_one_statement_per_line(root, language));
    issues.extend(check_clause_on_new_line(root, language));
    issues.extend(check_conditional_indentation(root, language));
    issues.extend(check_declarators_per_line(root, language));
    issues.extend(check_empty_comments(root, source, language));
    issues.extend(check_commented_out_code(root, source, language));
    issues.extend(check_numeric_separators(root, source, language));
    issues.extend(check_method_property_names(root, source, language));
    issues.extend(check_type_names(root, source, language));
    issues.extend(check_enum_names(root, source, language, options));
    issues.extend(check_enum_suffixes(root, source, language));
    issues.extend(check_exception_like_suffixes(root, source, language));
    issues.extend(check_parameter_shadows_method(root, source, language));
    issues.extend(check_type_name_matches_namespace(root, source, language));
    issues.extend(check_getter_named_methods(root, source, language));
    issues.extend(check_overloads_grouped(root, source, language));
    issues.extend(check_async_naming(root, source, language));
    issues.extend(check_logger_member_names(root, source, language, options));
    issues.extend(check_public_instance_fields(root, source, language));
    issues.extend(check_non_private_fields(root, source, language));
    issues.extend(check_visible_static_fields(root, source, language));
    issues.extend(check_public_constants(root, source, language));
    issues.extend(check_mutable_public_static_fields(root, source, language));
    issues.extend(check_sealed_protected_members(root, source, language));
    issues.extend(check_virtual_field_events(root, source, language));
    issues.extend(check_abstract_class_constructors(root, source, language));
    issues.extend(check_only_private_constructors(root, source, language));
    issues.extend(check_exception_visibility(root, source, language));
    issues.extend(check_out_ref_parameters(root, source, language));
    issues.extend(check_attribute_classes_sealed(root, source, language));
    issues.extend(check_iequatable_classes_sealed(root, source, language));
    issues.extend(check_private_types_sealed(root, source, language));
    issues.extend(check_member_visibility_above_type(root, source, language));
    issues.extend(check_optional_parameters(root, source, language));
    issues.extend(check_optional_attribute_on_ref_out_parameters(
        root, source, language,
    ));
    issues.extend(check_default_parameter_value_needs_optional(
        root, source, language,
    ));
    issues.extend(check_default_value_attribute_parameters(
        root, source, language,
    ));
    issues.extend(check_caller_information_parameters_last(
        root, source, language,
    ));
    issues.extend(check_pinvoke_visibility(root, source, language));
    issues.extend(check_native_methods_wrapped(root, source, language));
    issues.extend(check_public_pointer_signatures(root, source, language));
    issues.extend(check_multidimensional_arrays(root, source, language));
    issues.extend(check_public_multidimensional_parameters(
        root, source, language,
    ));
    issues.extend(check_enum_underlying_types(root, source, language));
    issues.extend(check_nested_generics_in_signatures(root, language));
    issues.extend(check_type_parameter_counts(root, language, options));
    issues.extend(check_unused_type_parameters_in_parameters(
        root, source, language,
    ));
    issues.extend(check_unused_type_parameters(root, source, language));
    issues.extend(check_async_void_methods(root, source, language));
    issues.extend(check_contextual_keyword_identifiers(root, source, language));
    issues.extend(check_goto_statements(root, language));
    issues.extend(check_break_statements(root, language));
    issues.extend(check_unsafe_code(root, source, language));
    issues.extend(check_arglist_usage(root, source, language));
    issues.extend(structural_issues(root, source, language, options));
    sort_issues(&mut issues);

    hoonarqube_ir::FileReport {
        path,
        language: language.prefix().to_string(),
        issues,
        metrics: file_metrics(tree.root_node(), source),
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

fn to_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn sort_issues(issues: &mut [Issue]) {
    issues.sort_by(|a, b| {
        (
            a.range.start.line,
            a.range.start.column,
            a.range.end.line,
            a.range.end.column,
            a.rule_key.as_str(),
            a.message.as_str(),
        )
            .cmp(&(
                b.range.start.line,
                b.range.start.column,
                b.range.end.line,
                b.range.end.column,
                b.rule_key.as_str(),
                b.message.as_str(),
            ))
    });
}

fn extension_of(path: &Path) -> Option<&str> {
    path.extension().and_then(|ext| ext.to_str())
}

fn file_metrics(root: Node<'_>, source: &str) -> hoonarqube_ir::FileMetrics {
    let _ = extension_of(Path::new(""));
    let lines = if source.is_empty() {
        0
    } else {
        to_u32(source.lines().count())
    };

    let mut code_lines = std::collections::BTreeSet::new();
    let mut comment_lines = std::collections::BTreeSet::new();
    collect_line_kinds(root, &mut code_lines, &mut comment_lines);
    // A line holding both code and a comment counts as code only.
    let comment_only: Vec<u32> = comment_lines.difference(&code_lines).copied().collect();

    hoonarqube_ir::FileMetrics {
        lines,
        code_lines: to_u32(code_lines.len()),
        comment_lines: to_u32(comment_only.len()),
    }
}

/// Gathers every Tier-A4 through A15 structural, function-metric,
/// expression, attribute-contract, member-contract, literal-content,
/// security deny-list, date/time or ASP.NET heuristic, logging-family, and
/// LINQ/format/assertion or misc API heuristic issue.
fn structural_issues(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_curly_braces(root, language));
    issues.extend(check_empty_blocks(root, language));
    issues.extend(check_empty_statements(root, language));
    issues.extend(check_redundant_parentheses(root, language));
    issues.extend(check_context_parentheses(root, language));
    issues.extend(check_mergeable_ifs(root, language));
    issues.extend(check_chains_end_with_else(root, language));
    issues.extend(check_switch_has_default(root, language));
    issues.extend(check_switch_case_counts(root, language));
    issues.extend(check_switch_section_statement_counts(
        root, language, options,
    ));
    issues.extend(check_switch_section_line_spans(root, language, options));
    issues.extend(check_nesting_depth(root, language, options));
    issues.extend(check_nested_code_blocks(root, language));
    issues.extend(check_function_lengths(root, language, options));
    issues.extend(check_method_parameter_counts(root, language, options));
    issues.extend(check_cyclomatic_complexity(root, source, language, options));
    issues.extend(check_cognitive_complexity(root, source, language, options));
    issues.extend(check_logical_operator_counts(
        root, source, language, options,
    ));
    issues.extend(check_empty_methods(root, source, language));
    issues.extend(check_finalizer_throws(root, language));
    issues.extend(check_empty_finalizers(root, language));
    issues.extend(check_property_getter_throws(root, source, language));
    issues.extend(check_write_only_properties(root, source, language));
    issues.extend(check_trivial_properties(root, source, language));
    issues.extend(check_abstract_member_mix(root, source, language));
    issues.extend(check_empty_classes_and_records(root, source, language));
    issues.extend(check_empty_interfaces(root, source, language));
    issues.extend(check_empty_namespaces(root, language));
    issues.extend(check_types_outside_namespaces(root, language));
    issues.extend(check_multiline_embedded_statements(root, language));
    issues.extend(check_nested_switches(root, language));
    issues.extend(check_default_clause_position(root, language));
    issues.extend(check_empty_cases_before_default(root, language));
    issues.extend(check_empty_default_clauses(root, language));
    issues.extend(check_condition_only_for_loops(root, language));
    issues.extend(check_for_increment_modifies_counter(root, source, language));
    issues.extend(check_local_shadowing(root, source, language));
    issues.extend(check_assignments_in_expressions(root, language));
    issues.extend(check_embedded_increments(root, language));
    issues.extend(check_self_assignments(root, source, language));
    issues.extend(check_redundant_boolean_comparisons(root, source, language));
    issues.extend(check_simplifiable_conditions(root, source, language));
    issues.extend(check_inverted_boolean_checks(root, language));
    issues.extend(check_doubled_prefix_operators(root, language));
    issues.extend(check_nan_comparisons(root, source, language));
    issues.extend(check_float_equality(root, language));
    issues.extend(check_self_relational_comparisons(root, source, language));
    issues.extend(check_negative_size_comparisons(root, source, language));
    issues.extend(check_indexof_positive_checks(root, source, language));
    issues.extend(check_shift_amounts(root, source, language));
    issues.extend(check_unnecessary_bit_operations(root, source, language));
    issues.extend(check_modulus_equality(root, language));
    issues.extend(check_nested_ternaries(root, language));
    issues.extend(check_this_is_checks(root, source, language));
    issues.extend(check_null_check_with_is(root, source, language));
    issues.extend(check_gettype_typeof_comparisons(root, source, language));
    issues.extend(check_null_or_empty_patterns(root, source, language));
    issues.extend(constant_fold_issues(root, source, language));
    issues.extend(attribute_contract_issues(root, source, language));
    issues.extend(member_contract_issues(root, source, language));
    issues.extend(literal_content_issues(root, source, language, options));
    issues.extend(usage_heuristic_issues(root, source, language));
    issues.extend(declaration_contract_issues(root, source, language));
    issues.extend(security_deny_list_issues(root, source, language));
    issues.extend(datetime_aspnet_issues(root, source, language));
    issues.extend(logging_issues(root, source, language, options));
    issues.extend(linq_api_issues(root, source, language));
    issues.extend(usage_analysis_issues(root, source, language));
    issues.extend(dataflow_cfg_issues(root, source, language));
    issues.extend(framework_api_issues(root, source, language));
    issues
}

/// Classifies every covered row as code or comment by walking the whole CST;
/// `comment` nodes mark comment rows, everything else marks code rows.
fn collect_line_kinds(
    node: Node<'_>,
    code_lines: &mut std::collections::BTreeSet<u32>,
    comment_lines: &mut std::collections::BTreeSet<u32>,
) {
    if node.kind() == "comment" {
        for row in node.start_position().row..=node.end_position().row {
            comment_lines.insert(to_u32(row));
        }
        return;
    }
    if node.child_count() == 0 && node.kind() != "ERROR" {
        for row in node.start_position().row..=node.end_position().row {
            code_lines.insert(to_u32(row));
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_line_kinds(child, code_lines, comment_lines);
    }
}

fn check_line_length(source: &str, language: CsLanguage, options: &AnalyzerOptions) -> Vec<Issue> {
    let maximum = usize::try_from(options.maximum_line_length).unwrap_or(usize::MAX);
    let rule_key = format!("{}:S103", language.prefix());
    let mut issues = Vec::new();
    for (zero_based, chunk) in source.split_inclusive('\n').enumerate() {
        let line = chunk.trim_end_matches(['\r', '\n']);
        let length = line.chars().count();
        if length > maximum {
            let line_number = to_u32(zero_based) + 1;
            issues.push(Issue {
                rule_key: rule_key.clone(),
                message: format!(
                    "This line exceeds the maximum allowed length of {} characters.",
                    options.maximum_line_length
                ),
                range: hoonarqube_ir::Range {
                    start: hoonarqube_ir::Pos {
                        line: line_number,
                        column: 0,
                    },
                    end: hoonarqube_ir::Pos {
                        line: line_number,
                        column: to_u32(length),
                    },
                },
            });
        }
    }
    issues
}

// ---------------------------------------------------------------------------
// Shared CST helpers
// ---------------------------------------------------------------------------

/// Pre-order walk over every named and anonymous child node.
fn walk_all<'t>(node: Node<'t>, visit: &mut impl FnMut(Node<'t>)) {
    visit(node);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_all(child, visit);
    }
}

/// Collects every node whose kind is listed, in document order.
fn collect_kinds<'t>(root: Node<'t>, kinds: &[&str]) -> Vec<Node<'t>> {
    let mut matched = Vec::new();
    walk_all(root, &mut |node| {
        if kinds.contains(&node.kind()) {
            matched.push(node);
        }
    });
    matched
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    node.utf8_text(source.as_bytes()).unwrap_or("")
}

fn pos_of(point: tree_sitter::Point) -> hoonarqube_ir::Pos {
    hoonarqube_ir::Pos {
        line: to_u32(point.row) + 1,
        column: to_u32(point.column),
    }
}

fn range_of(node: Node<'_>) -> hoonarqube_ir::Range {
    hoonarqube_ir::Range {
        start: pos_of(node.start_position()),
        end: pos_of(node.end_position()),
    }
}

fn issue(
    language: CsLanguage,
    rule: &str,
    message: impl Into<String>,
    range: hoonarqube_ir::Range,
) -> Issue {
    Issue {
        rule_key: format!("{}:{rule}", language.prefix()),
        message: message.into(),
        range,
    }
}

/// `^[A-Z][a-zA-Z0-9]*$` — `PascalCase` without underscores.
fn is_pascal_case(name: &str) -> bool {
    let mut chars = name.chars();
    if !matches!(chars.next(), Some(first) if first.is_ascii_uppercase()) {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric())
}

/// Strips a generic or invocation tail (`<…>`, `(…)`) and any qualification,
/// yielding the bare identifier (`System.Exception` / `ILogger<T>` → tail).
fn simple_name(type_text: &str) -> &str {
    let base = type_text.split(['<', '(']).next().unwrap_or(type_text);
    base.rsplit('.').next().unwrap_or(base)
}

/// Evaluates an `csharpsquid:S2342` naming format. Both catalog defaults are
/// understood natively (`PascalCase` words, plural trailing `s` for flags);
/// any custom format degrades to an exact literal match after stripping the
/// `^`/`$` anchors (this analyzer carries no regex engine).
fn matches_enum_format(name: &str, format: &str) -> bool {
    const PLAIN_DEFAULT: &str = "^([A-Z]{1,3}[a-z0-9]+)*([A-Z]{2})?$";
    const FLAGS_DEFAULT: &str = "^([A-Z]{1,3}[a-z0-9]+)*([A-Z]{2})?s$";
    match format {
        PLAIN_DEFAULT => is_pascal_case(name),
        FLAGS_DEFAULT => is_pascal_case(name) && name.ends_with('s'),
        literal => literal.trim_start_matches('^').trim_end_matches('$') == name,
    }
}

/// Evaluates the `csharpsquid:S6669` logger-name format. The catalog default
/// `^_?[Ll]og(ger)?$` is understood natively; custom formats degrade to an
/// exact literal match after stripping the anchors.
fn matches_logger_format(name: &str, format: &str) -> bool {
    const DEFAULT_FORMAT: &str = "^_?[Ll]og(ger)?$";
    if format != DEFAULT_FORMAT {
        return format.trim_start_matches('^').trim_end_matches('$') == name;
    }
    let bare = name.strip_prefix('_').unwrap_or(name);
    matches!(bare, "log" | "Log" | "logger" | "Logger")
}

// ---------------------------------------------------------------------------
// A1 — raw text / token / line scans
// ---------------------------------------------------------------------------

/// csharpsquid:S104 — file exceeds `maximumFileLocThreshold` lines of code.
fn check_file_loc(root: Node<'_>, language: CsLanguage, options: &AnalyzerOptions) -> Vec<Issue> {
    let mut code_lines = std::collections::BTreeSet::new();
    let mut comment_lines = std::collections::BTreeSet::new();
    collect_line_kinds(root, &mut code_lines, &mut comment_lines);
    let maximum = usize::try_from(options.maximum_file_loc_threshold).unwrap_or(usize::MAX);
    if code_lines.len() <= maximum {
        return Vec::new();
    }
    vec![issue(
        language,
        "S104",
        format!(
            "This file has {} lines of code which exceeds the authorized maximum of {}; split it into smaller files.",
            code_lines.len(),
            options.maximum_file_loc_threshold
        ),
        hoonarqube_ir::Range {
            start: hoonarqube_ir::Pos { line: 1, column: 0 },
            end: pos_of(root.end_position()),
        },
    )]
}

/// Column of the first tab inside a line's leading whitespace run.
fn leading_tab_column(line: &str) -> Option<u32> {
    let mut column = 0;
    for character in line.chars() {
        match character {
            '\t' => return Some(column),
            ' ' => column += 1,
            _ => return None,
        }
    }
    None
}

/// csharpsquid:S105 — no tab characters for indentation.
fn check_tabs(source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (index, chunk) in source.split_inclusive('\n').enumerate() {
        let line = chunk.trim_end_matches(['\r', '\n']);
        let Some(column) = leading_tab_column(line) else {
            continue;
        };
        let line_number = to_u32(index) + 1;
        issues.push(issue(
            language,
            "S105",
            "Replace all tab characters in this file by spaces.",
            hoonarqube_ir::Range {
                start: hoonarqube_ir::Pos {
                    line: line_number,
                    column,
                },
                end: hoonarqube_ir::Pos {
                    line: line_number,
                    column: column + 1,
                },
            },
        ));
    }
    issues
}

/// csharpsquid:S113 — files must end with a newline.
fn check_final_newline(source: &str, language: CsLanguage) -> Vec<Issue> {
    if source.is_empty() || source.ends_with('\n') {
        return Vec::new();
    }
    let line = to_u32(source.split_inclusive('\n').count());
    let column = to_u32(
        source
            .rsplit('\n')
            .next()
            .map_or(0, |chunk| chunk.chars().count()),
    );
    vec![issue(
        language,
        "S113",
        "Add a new line at the end of this file.",
        hoonarqube_ir::Range {
            start: hoonarqube_ir::Pos { line, column },
            end: hoonarqube_ir::Pos { line, column },
        },
    )]
}

/// csharpsquid:S1451 — required file header. An empty `header_format`
/// disables the check; regular-expression headers are not evaluated because
/// this analyzer carries no regex engine.
fn check_header(source: &str, language: CsLanguage, options: &AnalyzerOptions) -> Vec<Issue> {
    if options.header_format.is_empty() || options.header_is_regular_expression {
        return Vec::new();
    }
    let without_trailing_newline = options
        .header_format
        .strip_suffix('\n')
        .unwrap_or(&options.header_format);
    if source.starts_with(options.header_format.as_str())
        || source.starts_with(without_trailing_newline)
    {
        return Vec::new();
    }
    let column = to_u32(
        source
            .split('\n')
            .next()
            .map_or(0, |first_line| first_line.chars().count()),
    );
    vec![issue(
        language,
        "S1451",
        "Add or update the required header of this file.",
        hoonarqube_ir::Range {
            start: hoonarqube_ir::Pos { line: 1, column: 0 },
            end: hoonarqube_ir::Pos { line: 1, column },
        },
    )]
}

/// csharpsquid:S1109 — closing braces sit at the start of their line.
fn check_close_brace_column(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    walk_all(root, &mut |node| {
        if node.kind() == "}" && node.start_position().column != 0 {
            issues.push(issue(
                language,
                "S1109",
                "Move this closing curly brace to the beginning of its line.",
                range_of(node),
            ));
        }
    });
    issues
}

/// Containers whose direct children form statement lists; `global_statement`
/// wraps top-level statements in top-level-program files.
const STATEMENT_CONTAINER_KINDS: [&str; 6] = [
    "block",
    "compilation_unit",
    "declaration_list",
    "switch_body",
    "switch_section",
    "global_statement",
];

/// csharpsquid:S122 — statements live on separate lines. Only statements
/// directly inside statement-list containers count, so embedded bodies such
/// as `if (x) DoIt();` stay clean.
fn check_one_statement_per_line(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut statements_per_row: std::collections::BTreeMap<usize, Vec<Node>> =
        std::collections::BTreeMap::new();
    walk_all(root, &mut |node| {
        let kind = node.kind();
        if kind == "global_statement" || !kind.ends_with("_statement") {
            return;
        }
        let Some(parent) = node.parent() else {
            return;
        };
        if !STATEMENT_CONTAINER_KINDS.contains(&parent.kind()) {
            return;
        }
        statements_per_row
            .entry(node.start_position().row)
            .or_default()
            .push(node);
    });
    let mut issues = Vec::new();
    for row_statements in statements_per_row.values() {
        for statement in row_statements.iter().skip(1) {
            issues.push(issue(
                language,
                "S122",
                "Put each statement on its own line.",
                range_of(*statement),
            ));
        }
    }
    issues
}

/// csharpsquid:S3972 — `else`, `catch`, and `finally` start on a new line.
fn check_clause_on_new_line(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    walk_all(root, &mut |node| {
        let keyword_kinds: &[&str] = match node.kind() {
            "if_statement" => &["else"],
            "try_statement" => &["catch_clause", "finally_clause"],
            _ => return,
        };
        let mut cursor = node.walk();
        let mut previous_end_row: Option<usize> = None;
        for child in node.children(&mut cursor) {
            if keyword_kinds.contains(&child.kind())
                && previous_end_row == Some(child.start_position().row)
            {
                let keyword = child.kind().strip_suffix("_clause").unwrap_or(child.kind());
                issues.push(issue(
                    language,
                    "S3972",
                    format!("Move this \"{keyword}\" to a new line."),
                    range_of(child),
                ));
            }
            previous_end_row = Some(child.end_position().row);
        }
    });
    issues
}

/// Headers with brace-less single-statement bodies (`if`, loops, `using`,
/// `lock`, `fixed`).
const CONDITIONAL_HEADER_KINDS: [&str; 7] = [
    "if_statement",
    "for_statement",
    "foreach_statement",
    "while_statement",
    "using_statement",
    "lock_statement",
    "fixed_statement",
];

/// csharpsquid:S3973 — conditionally executed single lines must be denoted by
/// indentation: a brace-less body on its own line may not start at or before
/// its header's column.
fn check_conditional_indentation(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    walk_all(root, &mut |node| {
        if !CONDITIONAL_HEADER_KINDS.contains(&node.kind()) {
            return;
        }
        let header = node.start_position();
        let mut bodies: Vec<Node> = Vec::new();
        if node.kind() == "if_statement" {
            if let Some(consequence) = node.child_by_field_name("consequence") {
                bodies.push(consequence);
            }
            // An `else if(...)` chain link keeps its own header position.
            if let Some(alternative) = node.child_by_field_name("alternative")
                && alternative.kind() != "if_statement"
            {
                bodies.push(alternative);
            }
        } else {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.is_named()
                    && child.kind() != "block"
                    && child.kind().ends_with("_statement")
                {
                    bodies.push(child);
                }
            }
        }
        for body in bodies {
            let start = body.start_position();
            if start.row > header.row && start.column <= header.column {
                issues.push(issue(
                    language,
                    "S3973",
                    "Indent this statement to make its scope obvious.",
                    range_of(body),
                ));
            }
        }
    });
    issues
}

/// csharpsquid:S1659 — one variable declaration per line.
fn check_declarators_per_line(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    walk_all(root, &mut |node| {
        if node.kind() != "variable_declaration" {
            return;
        }
        let mut declarators_per_row: std::collections::BTreeMap<usize, Vec<Node>> =
            std::collections::BTreeMap::new();
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "variable_declarator" {
                declarators_per_row
                    .entry(child.start_position().row)
                    .or_default()
                    .push(child);
            }
        }
        for row_declarators in declarators_per_row.values() {
            for declarator in row_declarators.iter().skip(1) {
                issues.push(issue(
                    language,
                    "S1659",
                    "Declare each variable on its own line.",
                    range_of(*declarator),
                ));
            }
        }
    });
    issues
}

/// csharpsquid:S4663 — comments should not be empty.
fn check_empty_comments(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    walk_all(root, &mut |node| {
        if node.kind() != "comment" {
            return;
        }
        let text = node_text(node, source);
        let is_empty = if text.starts_with("///") {
            false
        } else if let Some(rest) = text.strip_prefix("//") {
            rest.trim().is_empty()
        } else if let Some(inner) = text.strip_prefix("/*") {
            let inner = inner.strip_suffix("*/").unwrap_or(inner);
            inner.chars().all(|c| c.is_whitespace() || c == '*')
        } else {
            false
        };
        if is_empty {
            issues.push(issue(
                language,
                "S4663",
                "Remove this empty comment.",
                range_of(node),
            ));
        }
    });
    issues
}

/// Keywords whose appearance at the start of a commented-out line suggests
/// real C# code rather than prose.
const CODE_KEYWORDS: [&str; 78] = [
    "abstract",
    "as",
    "async",
    "await",
    "base",
    "bool",
    "break",
    "byte",
    "case",
    "catch",
    "char",
    "checked",
    "class",
    "const",
    "continue",
    "decimal",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "event",
    "explicit",
    "extern",
    "false",
    "finally",
    "fixed",
    "float",
    "for",
    "foreach",
    "goto",
    "if",
    "implicit",
    "in",
    "int",
    "interface",
    "internal",
    "is",
    "lock",
    "long",
    "namespace",
    "new",
    "null",
    "object",
    "operator",
    "out",
    "override",
    "params",
    "private",
    "protected",
    "public",
    "readonly",
    "ref",
    "return",
    "sealed",
    "short",
    "sizeof",
    "stackalloc",
    "static",
    "string",
    "struct",
    "switch",
    "this",
    "throw",
    "true",
    "try",
    "typeof",
    "uint",
    "ulong",
    "unchecked",
    "unsafe",
    "ushort",
    "using",
    "var",
    "virtual",
    "void",
    "volatile",
    "while",
];

/// Heuristic: does this stripped comment line look like commented-out code?
fn looks_like_code(line: &str) -> bool {
    let trimmed = line.trim_end();
    if trimmed.is_empty() {
        return false;
    }
    let keyword_led = CODE_KEYWORDS.iter().any(|keyword| {
        trimmed.starts_with(keyword)
            && trimmed[keyword.len()..]
                .starts_with(|c: char| c.is_whitespace() || "({;=\"'<+".contains(c))
    });
    let statement_shaped = (trimmed.ends_with(';')
        && (trimmed.contains('(') || trimmed.contains('=')))
        || trimmed.ends_with('{')
        || trimmed.ends_with('}');
    statement_shaped || (keyword_led && (trimmed.contains(';') || trimmed.contains('(')))
}

/// Anchors an S125 issue at the start of a code-like comment run.
fn push_commented_out_code(issues: &mut Vec<Issue>, language: CsLanguage, start: Option<Node>) {
    let Some(start) = start else {
        return;
    };
    issues.push(issue(
        language,
        "S125",
        "Remove this commented-out code.",
        range_of(start),
    ));
}

/// csharpsquid:S125 — sections of code should not be commented out. Flags
/// runs of consecutive line comments (never `///` documentation) in which at
/// least one line is code-like.
fn check_commented_out_code(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut line_comments: Vec<Node> = Vec::new();
    walk_all(root, &mut |node| {
        let text = node_text(node, source);
        if node.kind() == "comment" && text.starts_with("//") && !text.starts_with("///") {
            line_comments.push(node);
        }
    });
    let mut issues = Vec::new();
    let mut run_start: Option<Node> = None;
    let mut run_has_code = false;
    let mut expected_next_row: Option<usize> = None;
    for comment in line_comments {
        if expected_next_row != Some(comment.start_position().row) {
            if run_has_code {
                push_commented_out_code(&mut issues, language, run_start);
            }
            run_start = Some(comment);
            run_has_code = false;
        }
        run_has_code |= looks_like_code(node_text(comment, source).trim_start_matches('/'));
        expected_next_row = Some(comment.end_position().row + 1);
    }
    if run_has_code {
        push_commented_out_code(&mut issues, language, run_start);
    }
    issues
}

/// csharpsquid:S2148 — large numbers use digit separators. Decimal literals
/// of 10 000 and above without an underscore are flagged; hexadecimal and
/// binary literals are exempt.
fn check_numeric_separators(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    walk_all(root, &mut |node| {
        if !matches!(node.kind(), "integer_literal" | "real_literal") {
            return;
        }
        let lowered = node_text(node, source).to_ascii_lowercase();
        if lowered.contains('_') || lowered.starts_with("0x") || lowered.starts_with("0b") {
            return;
        }
        if !is_large_unseparated_number(&lowered) {
            return;
        }
        issues.push(issue(
            language,
            "S2148",
            "Add digit separators (underscores) to this number.",
            range_of(node),
        ));
    });
    issues
}

fn is_large_unseparated_number(lowered: &str) -> bool {
    let digits = lowered.trim_end_matches(|c: char| c.is_ascii_alphabetic());
    if digits.contains('.') || digits.contains('e') {
        digits
            .parse::<f64>()
            .map_or(true, |value| value >= 10_000.0)
    } else {
        // Overflowing integer literals are certainly beyond the threshold.
        digits.parse::<i128>().map_or(true, |value| value >= 10_000)
    }
}

// ---------------------------------------------------------------------------
// A2 — naming conventions
// ---------------------------------------------------------------------------

const TYPE_DECLARATION_KINDS: [&str; 5] = [
    "class_declaration",
    "interface_declaration",
    "struct_declaration",
    "record_declaration",
    "enum_declaration",
];

fn declaration_kind_word(kind: &str) -> &str {
    match kind {
        "class_declaration" => "class",
        "interface_declaration" => "interface",
        "struct_declaration" => "struct",
        "record_declaration" => "record",
        _ => "enum",
    }
}

fn has_explicit_interface_specifier(node: Node<'_>) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|child| child.kind() == "explicit_interface_specifier")
}

/// csharpsquid:S100 — methods and properties are `PascalCase` without
/// underscores.
fn check_method_property_names(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const NAMING_PATTERN: &str = "'^([A-Z][a-z0-9]+)+([a-z0-9]+)?(_)?$'";
    let mut issues = Vec::new();
    walk_all(root, &mut |node| {
        let kind = node.kind();
        if kind != "method_declaration" && kind != "property_declaration" {
            return;
        }
        if has_explicit_interface_specifier(node) {
            return;
        }
        let Some(name) = node.child_by_field_name("name") else {
            return;
        };
        let name_text = node_text(name, source);
        if is_pascal_case(name_text) {
            return;
        }
        let subject = if kind == "method_declaration" {
            "method"
        } else {
            "property"
        };
        issues.push(issue(
            language,
            "S100",
            format!("Rename this {subject} to match the regular expression {NAMING_PATTERN}."),
            range_of(name),
        ));
    });
    issues
}

/// csharpsquid:S101 — types are `PascalCase` without underscores.
fn check_type_names(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const NAMING_PATTERN: &str = "'^([A-Z][a-z0-9]+)+([a-z0-9]+)?(_)?$'";
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        let Some(name) = type_node.child_by_field_name("name") else {
            continue;
        };
        let name_text = node_text(name, source);
        if is_pascal_case(name_text) {
            continue;
        }
        issues.push(issue(
            language,
            "S101",
            format!(
                "Rename this {} to match the regular expression {NAMING_PATTERN}.",
                declaration_kind_word(type_node.kind())
            ),
            range_of(name),
        ));
    }
    issues
}

fn enum_has_flags_attribute(enum_node: Node<'_>, source: &str) -> bool {
    let mut list_cursor = enum_node.walk();
    enum_node
        .children(&mut list_cursor)
        .filter(|child| child.kind() == "attribute_list")
        .any(|list| {
            let mut attribute_cursor = list.walk();
            list.children(&mut attribute_cursor)
                .filter(|attribute| attribute.kind() == "attribute")
                .filter_map(|attribute| attribute.child_by_field_name("name"))
                .any(|name| simple_name(node_text(name, source)) == "Flags")
        })
}

/// csharpsquid:S2342 — enumeration names follow the configured format; enums
/// decorated with `[Flags]` use `flagsAttributeFormat`.
fn check_enum_names(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for enum_node in collect_kinds(root, &["enum_declaration"]) {
        let Some(name) = enum_node.child_by_field_name("name") else {
            continue;
        };
        let name_text = node_text(name, source);
        let format = if enum_has_flags_attribute(enum_node, source) {
            options.flags_enum_naming_format.as_str()
        } else {
            options.enum_naming_format.as_str()
        };
        if matches_enum_format(name_text, format) {
            continue;
        }
        issues.push(issue(
            language,
            "S2342",
            format!("Rename this enumeration to match the regular expression '{format}'."),
            range_of(name),
        ));
    }
    issues
}

/// csharpsquid:S2344 — enum names carry neither an `Enum` nor a `Flags`
/// suffix.
fn check_enum_suffixes(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for enum_node in collect_kinds(root, &["enum_declaration"]) {
        let Some(name) = enum_node.child_by_field_name("name") else {
            continue;
        };
        let name_text = node_text(name, source);
        for suffix in ["Enum", "Flags"] {
            if name_text.ends_with(suffix) {
                issues.push(issue(
                    language,
                    "S2344",
                    format!("Remove this \"{suffix}\" suffix."),
                    range_of(name),
                ));
                break;
            }
        }
    }
    issues
}

/// csharpsquid:S3376 — classes extending `Attribute`, `EventArgs`, or
/// `Exception` end their names with that suffix.
fn check_exception_like_suffixes(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_node in collect_kinds(root, &["class_declaration"]) {
        let Some(name) = class_node.child_by_field_name("name") else {
            continue;
        };
        let name_text = node_text(name, source);
        let mut base_cursor = class_node.walk();
        let offending_tail = class_node
            .children(&mut base_cursor)
            .find(|child| child.kind() == "base_list")
            .and_then(|base_list| {
                let mut base_list_cursor = base_list.walk();
                base_list
                    .children(&mut base_list_cursor)
                    .map(|base| simple_name(node_text(base, source)))
                    .find(|tail| {
                        matches!(*tail, "Attribute" | "EventArgs" | "Exception")
                            && !name_text.ends_with(tail)
                    })
            });
        if let Some(tail) = offending_tail {
            issues.push(issue(
                language,
                "S3376",
                format!("Rename this class so its name ends with \"{tail}\"."),
                range_of(name),
            ));
        }
    }
    issues
}

/// csharpsquid:S3872 — parameter names do not duplicate their method's name
/// (case-insensitively).
fn check_parameter_shadows_method(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    walk_all(root, &mut |node| {
        if node.kind() != "method_declaration" {
            return;
        }
        let Some(method_name) = node.child_by_field_name("name") else {
            return;
        };
        let method_name = node_text(method_name, source);
        let Some(parameters) = node.child_by_field_name("parameters") else {
            return;
        };
        let mut parameter_cursor = parameters.walk();
        for parameter in parameters
            .children(&mut parameter_cursor)
            .filter(|child| child.kind() == "parameter")
        {
            let Some(parameter_name) = parameter.child_by_field_name("name") else {
                continue;
            };
            let parameter_text = node_text(parameter_name, source);
            if parameter_text.eq_ignore_ascii_case(method_name) {
                issues.push(issue(
                    language,
                    "S3872",
                    "Rename this parameter; it duplicates the name of its method.",
                    range_of(parameter_name),
                ));
            }
        }
    });
    issues
}

/// csharpsquid:S4041 — type names do not match namespace segments
/// (case-insensitively).
fn check_type_name_matches_namespace(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut namespace_segments: Vec<(&str, String)> = Vec::new();
    walk_all(root, &mut |node| {
        if node.kind() != "namespace_declaration" {
            return;
        }
        let Some(name) = node.child_by_field_name("name") else {
            return;
        };
        let full_name = node_text(name, source);
        for segment in full_name.split(['.', ':']).filter(|part| !part.is_empty()) {
            namespace_segments.push((segment, segment.to_ascii_lowercase()));
        }
    });
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        let Some(name) = type_node.child_by_field_name("name") else {
            continue;
        };
        let name_text = node_text(name, source);
        let lowered = name_text.to_ascii_lowercase();
        if let Some((original, _)) = namespace_segments
            .iter()
            .find(|(_, segment_lower)| *segment_lower == lowered)
        {
            issues.push(issue(
                language,
                "S4041",
                format!("Rename this type; its name matches namespace segment \"{original}\"."),
                range_of(name),
            ));
        }
    }
    issues
}

/// Direct members of a type's `declaration_list` body (empty for positional
/// records and enums).
fn type_members(type_node: Node<'_>) -> Vec<Node<'_>> {
    let Some(body) = type_node.child_by_field_name("body") else {
        return Vec::new();
    };
    if body.kind() != "declaration_list" {
        return Vec::new();
    }
    let mut cursor = body.walk();
    body.children(&mut cursor).collect()
}

/// csharpsquid:S4059 — accessor methods (`GetFoo`) do not duplicate property
/// names (`Foo`, case-insensitively).
fn check_getter_named_methods(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        let properties: Vec<(&str, String)> = type_members(type_node)
            .into_iter()
            .filter(|member| member.kind() == "property_declaration")
            .filter_map(|property| property.child_by_field_name("name"))
            .map(|name| {
                let text = node_text(name, source);
                (text, text.to_ascii_lowercase())
            })
            .collect();
        for member in type_members(type_node) {
            if member.kind() != "method_declaration" || has_explicit_interface_specifier(member) {
                continue;
            }
            let Some(name) = member.child_by_field_name("name") else {
                continue;
            };
            let method_name = node_text(name, source);
            let lowered = method_name.to_ascii_lowercase();
            let Some(candidate) = lowered.strip_prefix("get").filter(|rest| !rest.is_empty())
            else {
                continue;
            };
            if let Some((original, _)) = properties
                .iter()
                .find(|(_, property_lower)| *property_lower == candidate)
            {
                issues.push(issue(
                    language,
                    "S4059",
                    format!("Rename this accessor method; it duplicates property \"{original}\"."),
                    range_of(name),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S4136 — overloads of a method sit together within their type:
/// a reoccurrence after differently named members is flagged.
fn check_overloads_grouped(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        let mut last_index_by_name: Vec<(String, usize)> = Vec::new();
        for (index, member) in type_members(type_node).into_iter().enumerate() {
            if member.kind() != "method_declaration" || has_explicit_interface_specifier(member) {
                continue;
            }
            let Some(name) = member.child_by_field_name("name") else {
                continue;
            };
            let method_name = node_text(name, source);
            let lowered = method_name.to_ascii_lowercase();
            if let Some(entry) = last_index_by_name
                .iter_mut()
                .find(|(seen, _)| *seen == lowered)
            {
                if entry.1 + 1 != index {
                    issues.push(issue(
                        language,
                        "S4136",
                        format!("Move this overload next to the other \"{method_name}\" methods."),
                        range_of(name),
                    ));
                }
                entry.1 = index;
            } else {
                last_index_by_name.push((lowered, index));
            }
        }
    }
    issues
}

/// csharpsquid:S4261 — async methods take the `Async` suffix and no others.
/// Overridden methods keep whatever name they override.
fn check_async_naming(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    let non_interface_types: Vec<Node> = collect_kinds(root, &TYPE_DECLARATION_KINDS)
        .into_iter()
        .filter(|type_node| type_node.kind() != "interface_declaration")
        .collect();
    for type_node in non_interface_types {
        for member in type_members(type_node) {
            if member.kind() != "method_declaration" || has_explicit_interface_specifier(member) {
                continue;
            }
            let Some(name) = member.child_by_field_name("name") else {
                continue;
            };
            let mut modifier_cursor = member.walk();
            let modifiers: Vec<&str> = member
                .children(&mut modifier_cursor)
                .filter(|child| child.kind() == "modifier")
                .map(|modifier| node_text(modifier, source))
                .collect();
            if modifiers.contains(&"override") {
                continue;
            }
            let is_async = modifiers.contains(&"async");
            let method_name = node_text(name, source);
            let message = if is_async && !method_name.ends_with("Async") {
                Some("Add the \"Async\" suffix to the name of this method.")
            } else if !is_async && method_name.ends_with("Async") {
                Some("Remove the \"Async\" suffix from the name of this method.")
            } else {
                None
            };
            if let Some(message) = message {
                issues.push(issue(language, "S4261", message, range_of(name)));
            }
        }
    }
    issues
}

/// csharpsquid:S6669 — logger-typed fields and properties follow the
/// configured naming format.
fn check_logger_member_names(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    const LOGGER_TYPE_TAILS: [&str; 2] = ["Logger", "ILogger"];
    let mut issues = Vec::new();
    walk_all(root, &mut |node| {
        let kind = node.kind();
        if kind != "field_declaration" && kind != "property_declaration" {
            return;
        }
        let declared_type = if kind == "property_declaration" {
            node.child_by_field_name("type")
        } else {
            let mut cursor = node.walk();
            node.children(&mut cursor)
                .find(|child| child.kind() == "variable_declaration")
                .and_then(|declaration| declaration.child_by_field_name("type"))
        };
        let Some(declared_type) = declared_type else {
            return;
        };
        if !LOGGER_TYPE_TAILS.contains(&simple_name(node_text(declared_type, source))) {
            return;
        }
        let member_names: Vec<Node> = if kind == "property_declaration" {
            node.child_by_field_name("name").into_iter().collect()
        } else {
            let mut cursor = node.walk();
            node.children(&mut cursor)
                .filter(|child| child.kind() == "variable_declaration")
                .flat_map(|declaration| {
                    let mut declarator_cursor = declaration.walk();
                    declaration
                        .children(&mut declarator_cursor)
                        .collect::<Vec<Node>>()
                })
                .filter_map(|declarator| declarator.child_by_field_name("name"))
                .collect()
        };
        for name in member_names {
            let name_text = node_text(name, source);
            if matches_logger_format(name_text, &options.logger_name_format) {
                continue;
            }
            issues.push(issue(
                language,
                "S6669",
                format!(
                    "Rename \"{name_text}\" to match the regular expression \"{}\".",
                    options.logger_name_format
                ),
                range_of(name),
            ));
        }
    });
    issues
}
// ---------------------------------------------------------------------------
// A3 — modifiers & declaration shape
// ---------------------------------------------------------------------------

/// Modifiers (`public`, `static`, `const`, …) of a declaration, source order.
fn modifiers_of<'a>(declaration: Node<'_>, source: &'a str) -> Vec<&'a str> {
    let mut cursor = declaration.walk();
    declaration
        .children(&mut cursor)
        .filter(|child| child.kind() == "modifier")
        .map(|modifier| node_text(modifier, source))
        .collect()
}

/// Whether one keyword (`public`, `static`, `const`, …) is in `modifiers`.
fn has_modifier(modifiers: &[&str], wanted: &str) -> bool {
    modifiers.contains(&wanted)
}

fn has_any_accessibility(modifiers: &[&str]) -> bool {
    modifiers
        .iter()
        .any(|modifier| matches!(*modifier, "public" | "private" | "protected" | "internal"))
}

/// C# accessibility ladder: private < private protected < internal <
/// protected < protected internal < public. Undeclared ranks lowest; use
/// [`type_declared_rank`] for type declarations, where C# defaults differ.
fn accessibility_rank(modifiers: &[&str]) -> u8 {
    let has = |wanted: &str| has_modifier(modifiers, wanted);
    if has("public") {
        6
    } else if has("protected") && has("internal") {
        5
    } else if has("private") && has("protected") {
        2
    } else if has("protected") {
        4
    } else if has("internal") {
        3
    } else {
        1
    }
}

/// Declared rank of a *type* declaration, applying C# defaults: nested types
/// are private, types outside any other type are internal.
fn type_declared_rank(type_node: Node<'_>, source: &str) -> u8 {
    let modifiers = modifiers_of(type_node, source);
    if has_any_accessibility(&modifiers) {
        return accessibility_rank(&modifiers);
    }
    let mut ancestor = type_node.parent();
    while let Some(node) = ancestor {
        if TYPE_DECLARATION_KINDS.contains(&node.kind()) {
            return 1;
        }
        ancestor = node.parent();
    }
    3
}

/// Simple names of every base of a type declaration (`class D : B` → `B`),
/// with generic and qualification tails stripped.
fn base_simple_names<'a>(type_node: Node<'_>, source: &'a str) -> Vec<&'a str> {
    let mut names = Vec::new();
    let mut cursor = type_node.walk();
    for base_list in type_node
        .children(&mut cursor)
        .filter(|child| child.kind() == "base_list")
    {
        let mut list_cursor = base_list.walk();
        for base in base_list
            .children(&mut list_cursor)
            .filter(tree_sitter::Node::is_named)
        {
            names.push(simple_name(node_text(base, source)));
        }
    }
    names
}

/// Simple attribute names applied directly to `node`
/// (`[OptionalAttribute]` → `Optional`).
fn attributes_of<'a>(node: Node<'_>, source: &'a str) -> Vec<&'a str> {
    let mut names = Vec::new();
    let mut cursor = node.walk();
    for list in node
        .children(&mut cursor)
        .filter(|child| child.kind() == "attribute_list")
    {
        let mut list_cursor = list.walk();
        for attribute in list
            .children(&mut list_cursor)
            .filter(|child| child.kind() == "attribute")
        {
            if let Some(name) = attribute.child_by_field_name("name") {
                let text = simple_name(node_text(name, source));
                names.push(text.strip_suffix("Attribute").unwrap_or(text));
            }
        }
    }
    names
}

fn has_attribute(names: &[&str], wanted: &str) -> bool {
    names.contains(&wanted)
}

fn has_any_attribute(node: Node<'_>, source: &str, wanted: &[&str]) -> bool {
    wanted
        .iter()
        .any(|name| has_attribute(&attributes_of(node, source), name))
}

/// Parameters of a callable's `parameter_list`.
fn parameters_of(declaration: Node<'_>) -> Vec<Node<'_>> {
    let Some(list) = declaration.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let mut cursor = list.walk();
    list.children(&mut cursor)
        .filter(|child| child.kind() == "parameter")
        .collect()
}

/// Return-type and parameter regions of a callable; scans over these stay
/// out of bodies.
fn signature_regions(declaration: Node<'_>) -> Vec<Node<'_>> {
    ["returns", "type", "parameters"]
        .into_iter()
        .filter_map(|field| declaration.child_by_field_name(field))
        .collect()
}

fn subtree_contains_kind(root: Node<'_>, kind: &str) -> bool {
    !collect_kinds(root, &[kind]).is_empty()
}

/// True when one generic argument nests another (`List<Dictionary<K, V>>`).
fn has_nested_generics(root: Node<'_>) -> bool {
    fn walk(node: Node<'_>, depth: u32) -> bool {
        let depth = depth + u32::from(node.kind() == "generic_name");
        if depth > 1 {
            return true;
        }
        let mut cursor = node.walk();
        node.children(&mut cursor).any(|child| walk(child, depth))
    }
    walk(root, 0)
}

/// True for multi-dimensional arrays (`int[,]`); jagged arrays are nested
/// `array_type`s and never match.
fn is_multidimensional_array(array_type_node: Node<'_>, source: &str) -> bool {
    array_type_node
        .child_by_field_name("rank")
        .is_some_and(|rank| node_text(rank, source).contains(','))
}

fn has_ancestor_with_kind(mut node: Node<'_>, kinds: &[&str]) -> bool {
    while let Some(parent) = node.parent() {
        if kinds.contains(&parent.kind()) {
            return true;
        }
        node = parent;
    }
    false
}

/// Every type name used as a base somewhere in the file.
fn referenced_base_names(root: Node<'_>, source: &str) -> std::collections::HashSet<String> {
    collect_kinds(root, &TYPE_DECLARATION_KINDS)
        .iter()
        .flat_map(|declaration| base_simple_names(*declaration, source))
        .map(str::to_string)
        .collect()
}

/// Names of every `new T(...)` construction site in the file.
fn instantiated_type_names(root: Node<'_>, source: &str) -> std::collections::HashSet<String> {
    collect_kinds(root, &["object_creation_expression"])
        .into_iter()
        .filter_map(|creation| creation.child_by_field_name("type"))
        .map(|type_node| simple_name(node_text(type_node, source)).to_string())
        .collect()
}

/// A declaration's `type_parameter_list` together with its arity.
fn type_parameter_list_of(declaration: Node<'_>) -> Option<(Node<'_>, u32)> {
    let mut cursor = declaration.walk();
    let list = declaration
        .children(&mut cursor)
        .find(|child| child.kind() == "type_parameter_list")?;
    let mut list_cursor = list.walk();
    let count = to_u32(
        list.children(&mut list_cursor)
            .filter(|child| child.kind() == "type_parameter")
            .count(),
    );
    Some((list, count))
}

/// csharpsquid:S1104 — publicly accessible instance fields break
/// encapsulation; static and constant members belong to S2223 and S2339.
fn check_public_instance_fields(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for field in collect_kinds(root, &["field_declaration"]) {
        let modifiers = modifiers_of(field, source);
        if has_modifier(&modifiers, "public")
            && !has_modifier(&modifiers, "static")
            && !has_modifier(&modifiers, "const")
        {
            issues.push(issue(
                language,
                "S1104",
                "Make this field private and expose it through a property.",
                range_of(field),
            ));
        }
    }
    issues
}

/// csharpsquid:S2357 — fields should be private; constants are S2339's
/// territory.
fn check_non_private_fields(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for field in collect_kinds(root, &["field_declaration"]) {
        let modifiers = modifiers_of(field, source);
        if !has_modifier(&modifiers, "const") && accessibility_rank(&modifiers) > 1 {
            issues.push(issue(
                language,
                "S2357",
                "Make this field private.",
                range_of(field),
            ));
        }
    }
    issues
}

/// csharpsquid:S2223 — visible non-constant static fields hide shared
/// mutable state; `readonly` does not rescue them.
fn check_visible_static_fields(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for field in collect_kinds(root, &["field_declaration"]) {
        let modifiers = modifiers_of(field, source);
        if has_modifier(&modifiers, "static")
            && !has_modifier(&modifiers, "const")
            && has_any_accessibility(&modifiers)
        {
            issues.push(issue(
                language,
                "S2223",
                "Make this static field private.",
                range_of(field),
            ));
        }
    }
    issues
}

/// csharpsquid:S2339 — public constants leak implementation details into
/// every referencing assembly.
fn check_public_constants(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for field in collect_kinds(root, &["field_declaration"]) {
        let modifiers = modifiers_of(field, source);
        if has_modifier(&modifiers, "const") && has_modifier(&modifiers, "public") {
            issues.push(issue(
                language,
                "S2339",
                "Make this constant private.",
                range_of(field),
            ));
        }
    }
    issues
}

/// csharpsquid:S2386 — public static mutable fields invite races; only
/// `readonly` (or a property) settles them down.
fn check_mutable_public_static_fields(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for field in collect_kinds(root, &["field_declaration"]) {
        let modifiers = modifiers_of(field, source);
        if has_modifier(&modifiers, "public")
            && has_modifier(&modifiers, "static")
            && !has_modifier(&modifiers, "readonly")
            && !has_modifier(&modifiers, "const")
        {
            issues.push(issue(
                language,
                "S2386",
                "Make this field readonly or replace it with a property.",
                range_of(field),
            ));
        }
    }
    issues
}

/// csharpsquid:S2156 — sealed types cannot be inherited from, so their
/// `protected` members are dead weight.
fn check_sealed_protected_members(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(
        root,
        &[
            "class_declaration",
            "struct_declaration",
            "record_declaration",
        ],
    ) {
        if !has_modifier(&modifiers_of(type_node, source), "sealed") {
            continue;
        }
        for member in type_members(type_node) {
            if has_modifier(&modifiers_of(member, source), "protected") {
                issues.push(issue(
                    language,
                    "S2156",
                    "The 'protected' modifier is useless here: this type is sealed.",
                    range_of(member),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S2290 — virtual field-like events cannot be overridden in any
/// meaningful way.
fn check_virtual_field_events(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for event_field in collect_kinds(root, &["event_field_declaration"]) {
        if has_modifier(&modifiers_of(event_field, source), "virtual") {
            issues.push(issue(
                language,
                "S2290",
                "Remove the 'virtual' modifier from this event.",
                range_of(event_field),
            ));
        }
    }
    issues
}

/// csharpsquid:S3442 — abstract classes are constructed through derived
/// types, so public constructors mislead callers.
fn check_abstract_class_constructors(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &["class_declaration", "record_declaration"]) {
        if !has_modifier(&modifiers_of(type_node, source), "abstract") {
            continue;
        }
        for member in type_members(type_node) {
            if member.kind() == "constructor_declaration"
                && has_modifier(&modifiers_of(member, source), "public")
            {
                issues.push(issue(
                    language,
                    "S3442",
                    "Change this constructor's visibility to 'protected' or lower.",
                    range_of(member),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S3453 — classes with only inaccessible constructors can never
/// be instantiated. Classes constructed elsewhere in this file, protected-
/// constructor classes awaiting derivation, static classes, and partial
/// classes spanning files stay untouched.
fn check_only_private_constructors(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let instantiations = instantiated_type_names(root, source);
    let mut issues = Vec::new();
    for class_node in collect_kinds(root, &["class_declaration"]) {
        let modifiers = modifiers_of(class_node, source);
        if has_modifier(&modifiers, "static") || has_modifier(&modifiers, "partial") {
            continue;
        }
        let constructors: Vec<Node> = type_members(class_node)
            .into_iter()
            .filter(|member| member.kind() == "constructor_declaration")
            .collect();
        if constructors.is_empty()
            || !constructors
                .iter()
                .all(|ctor| accessibility_rank(&modifiers_of(*ctor, source)) <= 2)
        {
            continue;
        }
        let Some(name) = class_node.child_by_field_name("name") else {
            continue;
        };
        if instantiations.contains(simple_name(node_text(name, source))) {
            continue;
        }
        issues.push(issue(
            language,
            "S3453",
            "Make this class 'static' or give it a non-private constructor.",
            range_of(name),
        ));
    }
    issues
}

/// csharpsquid:S3871 — exception types should be public so callers can catch
/// them across assembly boundaries.
fn check_exception_visibility(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_node in collect_kinds(root, &["class_declaration"]) {
        let is_exception = base_simple_names(class_node, source)
            .iter()
            .any(|name| *name == "Exception" || name.ends_with("Exception"));
        if !is_exception || has_modifier(&modifiers_of(class_node, source), "public") {
            continue;
        }
        let Some(name) = class_node.child_by_field_name("name") else {
            continue;
        };
        issues.push(issue(
            language,
            "S3871",
            "Make this exception type public.",
            range_of(name),
        ));
    }
    issues
}

/// csharpsquid:S3874 — `out`/`ref` parameters obscure data flow; overrides
/// must mirror their base signature, so they stay untouched.
fn check_out_ref_parameters(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        let modifiers = modifiers_of(method, source);
        if has_modifier(&modifiers, "override") || has_explicit_interface_specifier(method) {
            continue;
        }
        for parameter in parameters_of(method) {
            let parameter_modifiers = modifiers_of(parameter, source);
            for modifier_kind in ["out", "ref"] {
                if has_modifier(&parameter_modifiers, modifier_kind) {
                    issues.push(issue(
                        language,
                        "S3874",
                        format!("Remove this '{modifier_kind}' parameter."),
                        range_of(parameter),
                    ));
                }
            }
        }
    }
    issues
}

/// csharpsquid:S4060 — non-abstract attribute classes should be sealed:
/// nothing is meant to derive from them.
fn check_attribute_classes_sealed(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_node in collect_kinds(root, &["class_declaration"]) {
        let derives_attribute = base_simple_names(class_node, source)
            .iter()
            .any(|name| *name == "Attribute" || name.ends_with("Attribute"));
        if !derives_attribute {
            continue;
        }
        let modifiers = modifiers_of(class_node, source);
        if has_modifier(&modifiers, "sealed")
            || has_modifier(&modifiers, "abstract")
            || has_modifier(&modifiers, "static")
        {
            continue;
        }
        let Some(name) = class_node.child_by_field_name("name") else {
            continue;
        };
        issues.push(issue(
            language,
            "S4060",
            "Mark this attribute class 'sealed' or 'abstract'.",
            range_of(name),
        ));
    }
    issues
}

/// csharpsquid:S4035 — IEquatable-implementing classes gain nothing from
/// being open for inheritance and should be sealed.
fn check_iequatable_classes_sealed(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_node in collect_kinds(root, &["class_declaration"]) {
        let implements_equatable = base_simple_names(class_node, source)
            .iter()
            .any(|name| name.starts_with("IEquatable"));
        if !implements_equatable {
            continue;
        }
        let modifiers = modifiers_of(class_node, source);
        if has_modifier(&modifiers, "sealed")
            || has_modifier(&modifiers, "abstract")
            || has_modifier(&modifiers, "static")
        {
            continue;
        }
        let Some(name) = class_node.child_by_field_name("name") else {
            continue;
        };
        issues.push(issue(
            language,
            "S4035",
            "Mark this class 'sealed'; it implements 'IEquatable'.",
            range_of(name),
        ));
    }
    issues
}

/// csharpsquid:S3260 — private types that nothing in this file derives from
/// gain nothing by staying open for inheritance. Partial types span files
/// and stay untouched.
fn check_private_types_sealed(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let bases = referenced_base_names(root, source);
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &["class_declaration", "record_declaration"]) {
        let modifiers = modifiers_of(type_node, source);
        if has_modifier(&modifiers, "partial")
            || has_modifier(&modifiers, "abstract")
            || has_modifier(&modifiers, "sealed")
            || has_modifier(&modifiers, "static")
        {
            continue;
        }
        // Private means explicitly marked, or nested without accessibility.
        if has_any_accessibility(&modifiers) && !has_modifier(&modifiers, "private") {
            continue;
        }
        if !has_any_accessibility(&modifiers) && type_declared_rank(type_node, source) != 1 {
            continue;
        }
        let Some(name) = type_node.child_by_field_name("name") else {
            continue;
        };
        if bases.contains(simple_name(node_text(name, source))) {
            continue;
        }
        issues.push(issue(
            language,
            "S3260",
            "Mark this private type 'sealed'.",
            range_of(name),
        ));
    }
    issues
}

/// csharpsquid:S3059 — members cannot be more visible than their container;
/// undeclared members default to private and never exceed it.
fn check_member_visibility_above_type(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    const MEMBER_KINDS: [&str; 14] = [
        "class_declaration",
        "struct_declaration",
        "record_declaration",
        "enum_declaration",
        "interface_declaration",
        "delegate_declaration",
        "method_declaration",
        "property_declaration",
        "event_declaration",
        "event_field_declaration",
        "field_declaration",
        "indexer_declaration",
        "operator_declaration",
        "constructor_declaration",
    ];
    let mut issues = Vec::new();
    for type_node in collect_kinds(
        root,
        &[
            "class_declaration",
            "struct_declaration",
            "record_declaration",
        ],
    ) {
        let type_rank = type_declared_rank(type_node, source);
        for member in type_members(type_node) {
            if !MEMBER_KINDS.contains(&member.kind()) {
                continue;
            }
            let member_modifiers = modifiers_of(member, source);
            if !has_any_accessibility(&member_modifiers)
                || accessibility_rank(&member_modifiers) <= type_rank
            {
                continue;
            }
            issues.push(issue(
                language,
                "S3059",
                "Reduce this member's visibility to match its container.",
                range_of(member),
            ));
        }
    }
    issues
}

/// csharpsquid:S2360 — optional parameters complicate overload resolution;
/// overrides and explicit implementations must repeat base defaults, so they
/// stay untouched.
fn check_optional_parameters(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        let modifiers = modifiers_of(method, source);
        if has_modifier(&modifiers, "override") || has_explicit_interface_specifier(method) {
            continue;
        }
        for parameter in parameters_of(method) {
            let mut cursor = parameter.walk();
            let has_default = parameter
                .children(&mut cursor)
                .any(|child| child.kind() == "=");
            if has_default {
                issues.push(issue(
                    language,
                    "S2360",
                    "Remove this optional parameter's default value.",
                    range_of(parameter),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S3447 — `[Optional]` cannot travel through by-reference
/// parameters.
fn check_optional_attribute_on_ref_out_parameters(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for parameter in collect_kinds(root, &["parameter"]) {
        let parameter_modifiers = modifiers_of(parameter, source);
        if !(has_modifier(&parameter_modifiers, "ref") || has_modifier(&parameter_modifiers, "out"))
        {
            continue;
        }
        if has_attribute(&attributes_of(parameter, source), "Optional") {
            issues.push(issue(
                language,
                "S3447",
                "Remove this '[Optional]' attribute; the parameter is by reference.",
                range_of(parameter),
            ));
        }
    }
    issues
}

/// csharpsquid:S3450 — `[DefaultParameterValue]` only takes effect together
/// with `[Optional]`.
fn check_default_parameter_value_needs_optional(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for parameter in collect_kinds(root, &["parameter"]) {
        let attributes = attributes_of(parameter, source);
        if has_attribute(&attributes, "DefaultParameterValue")
            && !has_attribute(&attributes, "Optional")
        {
            issues.push(issue(
                language,
                "S3450",
                "Add the '[Optional]' attribute next to '[DefaultParameterValue]'.",
                range_of(parameter),
            ));
        }
    }
    issues
}

/// csharpsquid:S3451 — on parameters, `[DefaultValue]` silently behaves like
/// `[DefaultParameterValue]`; spell the intent out.
fn check_default_value_attribute_parameters(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for parameter in collect_kinds(root, &["parameter"]) {
        if has_attribute(&attributes_of(parameter, source), "DefaultValue") {
            issues.push(issue(
                language,
                "S3451",
                "Use '[DefaultParameterValue]' instead of '[DefaultValue]'.",
                range_of(parameter),
            ));
        }
    }
    issues
}

/// csharpsquid:S3343 — caller-information parameters must trail everything
/// but a `params` array.
fn check_caller_information_parameters_last(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    const CALLER_ATTRIBUTES: [&str; 3] = ["CallerMemberName", "CallerLineNumber", "CallerFilePath"];
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration", "constructor_declaration"]) {
        let parameters = parameters_of(method);
        for (index, parameter) in parameters.iter().enumerate() {
            let attributes = attributes_of(*parameter, source);
            if !CALLER_ATTRIBUTES
                .iter()
                .any(|wanted| has_attribute(&attributes, wanted))
            {
                continue;
            }
            let blocked = parameters[index + 1..]
                .iter()
                .any(|later| !has_modifier(&modifiers_of(*later, source), "params"));
            if blocked {
                issues.push(issue(
                    language,
                    "S3343",
                    "Move this caller-information parameter to the end of the parameter list.",
                    range_of(*parameter),
                ));
            }
        }
    }
    issues
}
/// csharpsquid:S4214 — P/Invoke entry points stay hidden behind internal
/// wrappers; `protected` and `public` expose them.
fn check_pinvoke_visibility(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        let modifiers = modifiers_of(method, source);
        if !has_modifier(&modifiers, "extern")
            || !has_any_attribute(method, source, &["DllImport"])
            || !matches!(accessibility_rank(&modifiers), 4..=6)
        {
            continue;
        }
        let Some(name) = method.child_by_field_name("name") else {
            continue;
        };
        issues.push(issue(
            language,
            "S4214",
            "Make this P/Invoke method 'internal' or more restricted.",
            range_of(name),
        ));
    }
    issues
}

/// csharpsquid:S4200 — native entry points belong behind managed wrappers,
/// so every `DllImport` extern declaration is flagged.
fn check_native_methods_wrapped(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        let modifiers = modifiers_of(method, source);
        if !has_modifier(&modifiers, "extern") || !has_any_attribute(method, source, &["DllImport"])
        {
            continue;
        }
        let Some(name) = method.child_by_field_name("name") else {
            continue;
        };
        issues.push(issue(
            language,
            "S4200",
            "Wrap this native method behind a managed API.",
            range_of(name),
        ));
    }
    issues
}

/// csharpsquid:S4000 — public signatures must not leak pointer types into
/// managed callers.
fn check_public_pointer_signatures(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for declaration in collect_kinds(
        root,
        &[
            "method_declaration",
            "constructor_declaration",
            "operator_declaration",
            "indexer_declaration",
            "delegate_declaration",
        ],
    ) {
        if !has_modifier(&modifiers_of(declaration, source), "public") {
            continue;
        }
        let leaks_pointer = signature_regions(declaration)
            .iter()
            .any(|region| subtree_contains_kind(*region, "pointer_type"));
        if !leaks_pointer {
            continue;
        }
        let anchor = declaration
            .child_by_field_name("name")
            .unwrap_or(declaration);
        issues.push(issue(
            language,
            "S4000",
            "Do not expose pointer types in public signatures.",
            range_of(anchor),
        ));
    }
    issues
}

/// csharpsquid:S3967 — multi-dimensional arrays should be jagged arrays.
fn check_multidimensional_arrays(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for array_type_node in collect_kinds(root, &["array_type"]) {
        if is_multidimensional_array(array_type_node, source) {
            issues.push(issue(
                language,
                "S3967",
                "Use a jagged array instead of a multi-dimensional array.",
                range_of(array_type_node),
            ));
        }
    }
    issues
}

/// csharpsquid:S2368 — public methods must not surface multi-dimensional
/// array parameters.
fn check_public_multidimensional_parameters(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if !has_modifier(&modifiers_of(method, source), "public") {
            continue;
        }
        let offending = parameters_of(method).into_iter().any(|parameter| {
            parameter
                .child_by_field_name("type")
                .is_some_and(|type_node| {
                    collect_kinds(type_node, &["array_type"])
                        .iter()
                        .any(|array| is_multidimensional_array(*array, source))
                })
        });
        if !offending {
            continue;
        }
        let Some(name) = method.child_by_field_name("name") else {
            continue;
        };
        issues.push(issue(
            language,
            "S2368",
            "Remove this multi-dimensional array parameter from the public signature.",
            range_of(name),
        ));
    }
    issues
}

/// csharpsquid:S4022 — enums should stick to `int` storage.
fn check_enum_underlying_types(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for enum_node in collect_kinds(root, &["enum_declaration"]) {
        let mut cursor = enum_node.walk();
        let Some(base_list) = enum_node
            .children(&mut cursor)
            .find(|child| child.kind() == "base_list")
        else {
            continue;
        };
        let mut list_cursor = base_list.walk();
        let underlying = base_list
            .children(&mut list_cursor)
            .find(tree_sitter::Node::is_named)
            .map(|base| simple_name(node_text(base, source)));
        if underlying.is_none_or(|stored| matches!(stored, "int" | "Int32")) {
            continue;
        }
        let Some(name) = enum_node.child_by_field_name("name") else {
            continue;
        };
        issues.push(issue(
            language,
            "S4022",
            "Use 'int' as the underlying type of this enum.",
            range_of(name),
        ));
    }
    issues
}

/// csharpsquid:S4017 — nested generic types resist inference; signatures
/// should stay shallow.
fn check_nested_generics_in_signatures(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for declaration in collect_kinds(
        root,
        &[
            "method_declaration",
            "delegate_declaration",
            "operator_declaration",
            "indexer_declaration",
        ],
    ) {
        let nests_generics = signature_regions(declaration)
            .iter()
            .any(|region| has_nested_generics(*region));
        if !nests_generics {
            continue;
        }
        let anchor = declaration
            .child_by_field_name("name")
            .unwrap_or(declaration);
        issues.push(issue(
            language,
            "S4017",
            "Refactor this signature to avoid nested generic types.",
            range_of(anchor),
        ));
    }
    issues
}

/// csharpsquid:S2436 — generic arity is capped per type (`max`) and per
/// method (`maxMethod`).
fn check_type_parameter_counts(
    root: Node<'_>,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    const TYPE_KINDS: [&str; 5] = [
        "class_declaration",
        "struct_declaration",
        "interface_declaration",
        "record_declaration",
        "delegate_declaration",
    ];
    let mut issues = Vec::new();
    for declaration in collect_kinds(root, &TYPE_KINDS) {
        if let Some((list, count)) = type_parameter_list_of(declaration) {
            let cap = options.maximum_generic_parameters_for_types;
            if count > cap {
                issues.push(issue(
                    language,
                    "S2436",
                    format!("Reduce the number of type parameters ({count} > {cap})."),
                    range_of(list),
                ));
            }
        }
    }
    for method in collect_kinds(root, &["method_declaration"]) {
        if let Some((list, count)) = type_parameter_list_of(method) {
            let cap = options.maximum_generic_parameters_for_methods;
            if count > cap {
                issues.push(issue(
                    language,
                    "S2436",
                    format!("Reduce the number of type parameters ({count} > {cap})."),
                    range_of(list),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S4018 — every method type parameter must appear in the
/// parameter list.
fn check_unused_type_parameters_in_parameters(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        let Some((list, _)) = type_parameter_list_of(method) else {
            continue;
        };
        let Some(parameters) = method.child_by_field_name("parameters") else {
            continue;
        };
        let used: std::collections::HashSet<&str> = collect_kinds(parameters, &["identifier"])
            .iter()
            .map(|identifier| node_text(*identifier, source))
            .collect();
        for parameter in collect_kinds(list, &["type_parameter"]) {
            let name = node_text(parameter, source);
            if !used.contains(name) {
                issues.push(issue(
                    language,
                    "S4018",
                    format!("Type parameter \"{name}\" never appears in the parameter list."),
                    range_of(parameter),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S2326 — type parameters unused anywhere in their declaration
/// are dead weight; constraint references count as usage. Shadowing between
/// nested scopes is ignored.
fn check_unused_type_parameters(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut declarations = collect_kinds(root, &TYPE_DECLARATION_KINDS);
    declarations.extend(collect_kinds(
        root,
        &["method_declaration", "delegate_declaration"],
    ));
    let mut issues = Vec::new();
    for declaration in declarations {
        let Some((list, _)) = type_parameter_list_of(declaration) else {
            continue;
        };
        let mut counts: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();
        for identifier in collect_kinds(declaration, &["identifier"]) {
            *counts.entry(node_text(identifier, source)).or_insert(0) += 1;
        }
        let declared: Vec<Node> = collect_kinds(list, &["type_parameter"]);
        for parameter in &declared {
            let name = node_text(*parameter, source);
            let occurrences_in_list = to_u32(
                declared
                    .iter()
                    .filter(|other| node_text(**other, source) == name)
                    .count(),
            );
            let uses_outside = counts
                .get(name)
                .copied()
                .unwrap_or(0)
                .saturating_sub(occurrences_in_list);
            if uses_outside == 0 {
                issues.push(issue(
                    language,
                    "S2326",
                    format!("Remove this unused type parameter \"{name}\"."),
                    range_of(*parameter),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S3168 — async methods returning void swallow exceptions and
/// cannot be awaited.
fn check_async_void_methods(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if !has_modifier(&modifiers_of(method, source), "async") {
            continue;
        }
        let returns_void = method
            .child_by_field_name("returns")
            .is_some_and(|returns| node_text(returns, source).trim() == "void");
        if !returns_void {
            continue;
        }
        let Some(name) = method.child_by_field_name("name") else {
            continue;
        };
        issues.push(issue(
            language,
            "S3168",
            "Return 'Task' instead of 'void' from this async method.",
            range_of(name),
        ));
    }
    issues
}

/// csharpsquid:S2306 — `async` and `await` are contextual keywords, never
/// identifiers.
fn check_contextual_keyword_identifiers(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for identifier in collect_kinds(root, &["identifier"]) {
        let text = node_text(identifier, source);
        if matches!(text, "async" | "await") {
            issues.push(issue(
                language,
                "S2306",
                format!("Rename \"{text}\"; it collides with a contextual keyword."),
                range_of(identifier),
            ));
        }
    }
    issues
}

/// csharpsquid:S907 — gotos destroy structured control flow.
fn check_goto_statements(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for statement in collect_kinds(root, &["goto_statement"]) {
        issues.push(issue(
            language,
            "S907",
            "Replace this 'goto' with structured control flow.",
            range_of(statement),
        ));
    }
    issues
}

/// csharpsquid:S1227 — bare `break`s belong to loops and switch sections
/// only.
fn check_break_statements(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for statement in collect_kinds(root, &["break_statement"]) {
        let legal_home = has_ancestor_with_kind(
            statement,
            &[
                "switch_section",
                "for_statement",
                "foreach_statement",
                "while_statement",
                "do_statement",
            ],
        );
        if !legal_home {
            issues.push(issue(
                language,
                "S1227",
                "Remove this 'break'; it exits neither a loop nor a switch section.",
                range_of(statement),
            ));
        }
    }
    issues
}

/// csharpsquid:S6640 — unsafe blocks and unsafe declarations opt out of
/// memory-safety guarantees.
fn check_unsafe_code(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const UNSAFE_DECLARATION_KINDS: [&str; 11] = [
        "class_declaration",
        "struct_declaration",
        "record_declaration",
        "interface_declaration",
        "delegate_declaration",
        "field_declaration",
        "event_field_declaration",
        "method_declaration",
        "property_declaration",
        "indexer_declaration",
        "operator_declaration",
    ];
    let mut issues = Vec::new();
    for statement in collect_kinds(root, &["unsafe_statement"]) {
        issues.push(issue(
            language,
            "S6640",
            "Remove this unsafe block.",
            range_of(statement),
        ));
    }
    for declaration in collect_kinds(root, &UNSAFE_DECLARATION_KINDS) {
        if !has_modifier(&modifiers_of(declaration, source), "unsafe") {
            continue;
        }
        let anchor = declaration
            .child_by_field_name("name")
            .unwrap_or(declaration);
        issues.push(issue(
            language,
            "S6640",
            "Remove the 'unsafe' modifier from this declaration.",
            range_of(anchor),
        ));
    }
    issues
}

/// csharpsquid:S4061 — `params` replaced `__arglist` long ago.
fn check_arglist_usage(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for identifier in collect_kinds(root, &["identifier"]) {
        if node_text(identifier, source) == "__arglist" {
            issues.push(issue(
                language,
                "S4061",
                "Use 'params' instead of '__arglist'.",
                range_of(identifier),
            ));
        }
    }
    issues
}
// ---------------------------------------------------------------------------
// A4 — structural statement checks
// ---------------------------------------------------------------------------

/// Headers embedding a brace-less statement body.
const EMBEDDED_HEADER_KINDS: [&str; 8] = [
    "if_statement",
    "for_statement",
    "foreach_statement",
    "while_statement",
    "do_statement",
    "using_statement",
    "lock_statement",
    "fixed_statement",
];

/// Declarations whose `block` children are callable bodies.
const CALLABLE_BODY_OWNER_KINDS: [&str; 6] = [
    "method_declaration",
    "constructor_declaration",
    "destructor_declaration",
    "operator_declaration",
    "accessor_declaration",
    "local_function_statement",
];

/// Control-flow constructs counted by the S134 nesting-depth walk.
const NESTING_CONSTRUCT_KINDS: [&str; 12] = [
    "if_statement",
    "for_statement",
    "foreach_statement",
    "while_statement",
    "do_statement",
    "switch_statement",
    "try_statement",
    "catch_clause",
    "finally_clause",
    "using_statement",
    "lock_statement",
    "fixed_statement",
];

/// Every parent of `node`, nearest first.
fn ancestors_of(node: Node<'_>) -> impl Iterator<Item = Node<'_>> {
    std::iter::successors(node.parent(), tree_sitter::Node::parent)
}

/// True when `node` sits under an `ERROR`/missing region of a recovered
/// tree; such regions carry unreliable structure, so checks skip them.
fn is_error_tainted(node: Node<'_>) -> bool {
    node.is_error() || node.is_missing() || ancestors_of(node).any(|ancestor| ancestor.is_error())
}

/// True for nodes forming statements: explicit `block`s and `*_statement`s.
fn is_statement_kind(kind: &str) -> bool {
    kind == "block" || kind.ends_with("_statement")
}

/// Statement bodies embedded in a control header, source order: the
/// consequence first, the `else` alternative last.
fn embedded_bodies(header: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = header.walk();
    header
        .children(&mut cursor)
        .filter(|child| child.is_named() && is_statement_kind(child.kind()))
        .collect()
}

/// The statement following an `else` keyword, when present.
fn else_alternative(if_statement: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = if_statement.walk();
    let mut past_else = false;
    for child in if_statement.children(&mut cursor) {
        if child.kind() == "else" {
            past_else = true;
        } else if past_else && child.is_named() {
            return Some(child);
        }
    }
    None
}

/// Whether `node` is the alternative branch of an enclosing `if_statement`.
fn is_else_alternative(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "if_statement" && else_alternative(parent) == Some(node)
    })
}

/// The `switch_body` of a `switch_statement`.
fn switch_body_of(switch_statement: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = switch_statement.walk();
    switch_statement
        .children(&mut cursor)
        .find(|child| child.kind() == "switch_body")
}

/// Sections of a `switch_body`, source order.
fn switch_sections_of(switch_body: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = switch_body.walk();
    switch_body
        .children(&mut cursor)
        .filter(|child| child.kind() == "switch_section")
        .collect()
}

/// Whether a section carries a `default` label.
fn section_has_default(section: Node<'_>) -> bool {
    let mut cursor = section.walk();
    section
        .children(&mut cursor)
        .any(|child| child.kind() == "default")
}

/// Statements directly inside a section; labels are anonymous tokens and
/// never appear here.
fn section_statements(section: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = section.walk();
    section
        .children(&mut cursor)
        .filter(|child| child.is_named() && is_statement_kind(child.kind()))
        .collect()
}

/// The initializer, condition, and update clauses of a `for_statement`,
/// split on its semicolons.
fn for_clauses(for_statement: Node<'_>) -> (Option<Node<'_>>, Option<Node<'_>>, Option<Node<'_>>) {
    let mut clauses = [None, None, None];
    let mut semicolons_seen = 0_usize;
    let mut cursor = for_statement.walk();
    for child in for_statement.children(&mut cursor) {
        if child.kind() == ")" {
            break;
        }
        if child.kind() == ";" {
            semicolons_seen += 1;
        } else if child.is_named() && semicolons_seen < clauses.len() {
            clauses[semicolons_seen] = Some(child);
        }
    }
    (clauses[0], clauses[1], clauses[2])
}

/// Loop-counter candidate of an initializer clause: its first identifier
/// (`int i = 0`, `i = 0`, both spellings alike).
fn counter_name<'a>(initializer: Node<'_>, source: &'a str) -> Option<&'a str> {
    collect_kinds(initializer, &["identifier"])
        .first()
        .map(|identifier| node_text(*identifier, source))
}

/// csharpsquid:S121 — control structures wrap their bodies in curly braces.
fn check_curly_braces(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for header in collect_kinds(root, &EMBEDDED_HEADER_KINDS) {
        if is_error_tainted(header) {
            continue;
        }
        for body in embedded_bodies(header) {
            if body.kind() != "block" {
                issues.push(issue(
                    language,
                    "S121",
                    "Add curly braces around this embedded statement.",
                    range_of(body),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S108 — blocks are not left empty. Commented placeholder
/// bodies stay clean; callable bodies belong to S1186 and S3880.
fn check_empty_blocks(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for block in collect_kinds(root, &["block"]) {
        if is_error_tainted(block) {
            continue;
        }
        let owned_by_callable = block
            .parent()
            .is_some_and(|owner| CALLABLE_BODY_OWNER_KINDS.contains(&owner.kind()));
        let mut cursor = block.walk();
        let has_content = block.children(&mut cursor).any(|child| child.is_named());
        if !owned_by_callable && !has_content {
            issues.push(issue(
                language,
                "S108",
                "Either populate this block or remove it.",
                range_of(block),
            ));
        }
    }
    issues
}

/// csharpsquid:S1116 — stray empty statements are removed.
fn check_empty_statements(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["empty_statement"])
        .into_iter()
        .filter(|statement| !is_error_tainted(*statement))
        .map(|statement| {
            issue(
                language,
                "S1116",
                "Remove this empty statement.",
                range_of(statement),
            )
        })
        .collect()
}

/// csharpsquid:S1110 — a parenthesis pair wrapping only another pair is
/// redundant.
fn check_redundant_parentheses(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for parenthesized in collect_kinds(root, &["parenthesized_expression"]) {
        if is_error_tainted(parenthesized) {
            continue;
        }
        let mut cursor = parenthesized.walk();
        let wraps_single_pair = parenthesized.named_child_count() == 1
            && parenthesized
                .children(&mut cursor)
                .all(|child| !child.is_named() || child.kind() == "parenthesized_expression");
        if wraps_single_pair {
            issues.push(issue(
                language,
                "S1110",
                "Remove this redundant pair of parentheses.",
                range_of(parenthesized),
            ));
        }
    }
    issues
}

/// csharpsquid:S3235 — parentheses around return values and arguments
/// cannot change precedence there and are noise.
fn check_context_parentheses(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for parenthesized in collect_kinds(root, &["parenthesized_expression"]) {
        if is_error_tainted(parenthesized) {
            continue;
        }
        let context = parenthesized.parent().map(|parent| parent.kind());
        if matches!(context, Some("return_statement" | "argument")) {
            issues.push(issue(
                language,
                "S3235",
                "Remove these unnecessary parentheses.",
                range_of(parenthesized),
            ));
        }
    }
    issues
}

/// csharpsquid:S1066 — an `else`-less `if` holding exactly one nested `if`
/// merges into a single condition.
fn check_mergeable_ifs(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    fn mergeable_block(block: Node<'_>) -> bool {
        let statements = embedded_bodies(block);
        statements.len() == 1
            && statements[0].kind() == "if_statement"
            && else_alternative(statements[0]).is_none()
    }
    let mut issues = Vec::new();
    for if_statement in collect_kinds(root, &["if_statement"]) {
        if is_error_tainted(if_statement) || else_alternative(if_statement).is_some() {
            continue;
        }
        let Some(consequence) = embedded_bodies(if_statement).first().copied() else {
            continue;
        };
        let mergeable = match consequence.kind() {
            "if_statement" => else_alternative(consequence).is_none(),
            "block" => mergeable_block(consequence),
            _ => false,
        };
        if mergeable {
            issues.push(issue(
                language,
                "S1066",
                "Merge this if statement with the nested one.",
                range_of(if_statement),
            ));
        }
    }
    issues
}

/// csharpsquid:S126 — `else if` chains end with a terminal `else`.
fn check_chains_end_with_else(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for head in collect_kinds(root, &["if_statement"]) {
        if is_error_tainted(head) || is_else_alternative(head) {
            continue;
        }
        let mut current = head;
        loop {
            match else_alternative(current) {
                None => {
                    if current != head {
                        issues.push(issue(
                            language,
                            "S126",
                            "Add an 'else' clause to close this 'else if' chain.",
                            range_of(current),
                        ));
                    }
                    break;
                }
                Some(alternative) if alternative.kind() == "if_statement" => {
                    current = alternative;
                }
                Some(_) => break,
            }
        }
    }
    issues
}

/// csharpsquid:S131 — every `switch` carries a `default` clause.
fn check_switch_has_default(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for switch_statement in collect_kinds(root, &["switch_statement"]) {
        if is_error_tainted(switch_statement) {
            continue;
        }
        let has_default = switch_body_of(switch_statement)
            .is_some_and(|body| subtree_contains_kind(body, "default"));
        if !has_default {
            issues.push(issue(
                language,
                "S131",
                "Add a 'default' clause to this switch.",
                range_of(switch_statement),
            ));
        }
    }
    issues
}

/// csharpsquid:S1301 — switches replace at least three-way dispatch;
/// smaller ones read better as `if`/`else`.
fn check_switch_case_counts(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for switch_statement in collect_kinds(root, &["switch_statement"]) {
        if is_error_tainted(switch_statement) {
            continue;
        }
        let Some(body) = switch_body_of(switch_statement) else {
            continue;
        };
        let case_labels = collect_kinds(body, &["case"]).len();
        if case_labels < 3 {
            issues.push(issue(
                language,
                "S1301",
                "Replace this switch with an 'if'/'else' chain; it has fewer than three cases.",
                range_of(switch_statement),
            ));
        }
    }
    issues
}

/// csharpsquid:S1479 — a switch section holds at most the tolerated number
/// of statements.
fn check_switch_section_statement_counts(
    root: Node<'_>,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for switch_statement in collect_kinds(root, &["switch_statement"]) {
        if is_error_tainted(switch_statement) {
            continue;
        }
        for section in switch_body_of(switch_statement)
            .map(switch_sections_of)
            .unwrap_or_default()
        {
            let count = to_u32(section_statements(section).len());
            if count > options.maximum_switch_section_statements {
                issues.push(issue(
                    language,
                    "S1479",
                    format!("Split this 'case' block; it contains {count} statements."),
                    range_of(section),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S1151 — a switch section fits within the tolerated span.
fn check_switch_section_line_spans(
    root: Node<'_>,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for switch_statement in collect_kinds(root, &["switch_statement"]) {
        if is_error_tainted(switch_statement) {
            continue;
        }
        for section in switch_body_of(switch_statement)
            .map(switch_sections_of)
            .unwrap_or_default()
        {
            let height = to_u32(section.end_position().row - section.start_position().row + 1);
            if height > options.maximum_switch_section_lines {
                issues.push(issue(
                    language,
                    "S1151",
                    format!("Reduce this 'case' block; it spans {height} lines."),
                    range_of(section),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S134 — control-flow nesting stays within the configured
/// depth.
fn check_nesting_depth(
    root: Node<'_>,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for construct in collect_kinds(root, &NESTING_CONSTRUCT_KINDS) {
        if is_error_tainted(construct) {
            continue;
        }
        let depth = ancestors_of(construct)
            .filter(|ancestor| NESTING_CONSTRUCT_KINDS.contains(&ancestor.kind()))
            .count();
        if to_u32(depth) > options.maximum_nesting_level {
            issues.push(issue(
                language,
                "S134",
                format!("Reduce this code's nesting depth ({depth} levels deep)."),
                range_of(construct),
            ));
        }
    }
    issues
}

/// csharpsquid:S1199 — plain code blocks nest only through control flow.
fn check_nested_code_blocks(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for block in collect_kinds(root, &["block"]) {
        if is_error_tainted(block) {
            continue;
        }
        if block
            .parent()
            .is_some_and(|parent| parent.kind() == "block")
        {
            issues.push(issue(
                language,
                "S1199",
                "Remove this nested code block.",
                range_of(block),
            ));
        }
    }
    issues
}

/// csharpsquid:S2681 — multi-line embedded bodies wear braces so no later
/// line can masquerade as part of the body.
fn check_multiline_embedded_statements(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for header in collect_kinds(root, &EMBEDDED_HEADER_KINDS) {
        if is_error_tainted(header) {
            continue;
        }
        for body in embedded_bodies(header) {
            if body.kind() != "block" && body.start_position().row != body.end_position().row {
                issues.push(issue(
                    language,
                    "S2681",
                    "Enclose this multi-line body in curly braces.",
                    range_of(body),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S1821 — switch statements do not nest inside other switches.
fn check_nested_switches(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for switch_statement in collect_kinds(root, &["switch_statement"]) {
        if is_error_tainted(switch_statement) {
            continue;
        }
        let nested_in_switch = ancestors_of(switch_statement)
            .take_while(|ancestor| !CALLABLE_BODY_OWNER_KINDS.contains(&ancestor.kind()))
            .any(|ancestor| ancestor.kind() == "switch_statement");
        if nested_in_switch {
            issues.push(issue(
                language,
                "S1821",
                "Refactor this nested 'switch' into a separate method.",
                range_of(switch_statement),
            ));
        }
    }
    issues
}

/// csharpsquid:S4524 — the `default` clause leads or trails the sections.
fn check_default_clause_position(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for switch_statement in collect_kinds(root, &["switch_statement"]) {
        if is_error_tainted(switch_statement) {
            continue;
        }
        let Some(body) = switch_body_of(switch_statement) else {
            continue;
        };
        let sections = switch_sections_of(body);
        let Some(index) = sections.iter().position(|s| section_has_default(*s)) else {
            continue;
        };
        if index > 0 && index != sections.len() - 1 {
            issues.push(issue(
                language,
                "S4524",
                "Move this 'default' clause first or last among the sections.",
                range_of(sections[index]),
            ));
        }
    }
    issues
}

/// csharpsquid:S3458 — an empty `case` stack falling straight into
/// `default` drops its labels.
fn check_empty_cases_before_default(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for switch_statement in collect_kinds(root, &["switch_statement"]) {
        if is_error_tainted(switch_statement) {
            continue;
        }
        let Some(body) = switch_body_of(switch_statement) else {
            continue;
        };
        for pair in switch_sections_of(body).windows(2) {
            if section_statements(pair[0]).is_empty() && section_has_default(pair[1]) {
                issues.push(issue(
                    language,
                    "S3458",
                    "Remove this empty 'case'; it falls through to 'default'.",
                    range_of(pair[0]),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S3532 — empty `default` clauses are removed.
fn check_empty_default_clauses(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for switch_statement in collect_kinds(root, &["switch_statement"]) {
        if is_error_tainted(switch_statement) {
            continue;
        }
        let Some(body) = switch_body_of(switch_statement) else {
            continue;
        };
        for section in switch_sections_of(body) {
            if section_has_default(section) && section_statements(section).is_empty() {
                issues.push(issue(
                    language,
                    "S3532",
                    "Remove this empty 'default' clause.",
                    range_of(section),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S1264 — a `for` with neither initializer nor update is a
/// `while`.
fn check_condition_only_for_loops(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for for_statement in collect_kinds(root, &["for_statement"]) {
        if is_error_tainted(for_statement) {
            continue;
        }
        let (initializer, _, update) = for_clauses(for_statement);
        if initializer.is_none() && update.is_none() {
            issues.push(issue(
                language,
                "S1264",
                "Convert this 'for' into a 'while'.",
                range_of(for_statement),
            ));
        }
    }
    issues
}

/// csharpsquid:S1994 — the increment clause drives the loop counter.
fn check_for_increment_modifies_counter(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for for_statement in collect_kinds(root, &["for_statement"]) {
        if is_error_tainted(for_statement) {
            continue;
        }
        let (Some(initializer), _, update) = for_clauses(for_statement) else {
            continue;
        };
        let Some(counter) = counter_name(initializer, source) else {
            continue;
        };
        let modifies_counter = update.is_some_and(|clause| {
            collect_kinds(clause, &["identifier"])
                .iter()
                .any(|identifier| node_text(*identifier, source) == counter)
        });
        if !modifies_counter {
            issues.push(issue(
                language,
                "S1994",
                format!("Update the counter '{counter}' inside this loop's increment."),
                range_of(for_statement),
            ));
        }
    }
    issues
}
/// The `block` body of a callable, when it has one (abstract and
/// expression-bodied members do not).
fn body_of(declaration: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = declaration.walk();
    declaration
        .children(&mut cursor)
        .find(|child| child.kind() == "block")
}

/// A declaration's name identifier, falling back to the whole declaration.
fn name_anchor(declaration: Node<'_>) -> Node<'_> {
    declaration
        .child_by_field_name("name")
        .unwrap_or(declaration)
}

/// Whether the declaration carries any attribute directly.
fn is_attributed(declaration: Node<'_>, source: &str) -> bool {
    !attributes_of(declaration, source).is_empty()
}

/// The operator token of a binary expression (`&&`, `<<`, `==`, ...).
fn binary_operator<'a>(expression: Node<'_>, source: &'a str) -> &'a str {
    let mut cursor = expression.walk();
    expression
        .children(&mut cursor)
        .find(|child| !child.is_named())
        .map_or("", |token| node_text(token, source))
}

/// csharpsquid:S138 — function bodies stay within the tolerated span.
fn check_function_lengths(
    root: Node<'_>,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for function in collect_kinds(root, &CALLABLE_BODY_OWNER_KINDS) {
        if is_error_tainted(function) {
            continue;
        }
        let Some(body) = body_of(function) else {
            continue;
        };
        let height = to_u32(body.end_position().row - body.start_position().row + 1);
        if height > options.maximum_function_lines {
            issues.push(issue(
                language,
                "S138",
                format!("Reduce this function's size; its body spans {height} lines."),
                range_of(name_anchor(function)),
            ));
        }
    }
    issues
}

/// csharpsquid:S107 — methods and constructors take at most the tolerated
/// number of parameters.
fn check_method_parameter_counts(
    root: Node<'_>,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    const KINDS: [&str; 2] = ["method_declaration", "constructor_declaration"];
    let mut issues = Vec::new();
    for method in collect_kinds(root, &KINDS) {
        if is_error_tainted(method) {
            continue;
        }
        let count = parameters_of(method).len();
        if to_u32(count) > options.maximum_method_parameters {
            issues.push(issue(
                language,
                "S107",
                format!(
                    "Reduce the number of parameters ({count} > {}).",
                    options.maximum_method_parameters
                ),
                range_of(name_anchor(method)),
            ));
        }
    }
    issues
}

/// Decision points of the S1541 cyclomatic walk: branching statements,
/// case labels, catches, ternaries, null-coalescing, and short-circuiting
/// operators. Nested local functions count toward their enclosing member.
fn cyclomatic_decisions(body: Node<'_>, source: &str) -> u32 {
    let mut decisions = 0_u32;
    walk_all(body, &mut |node| match node.kind() {
        "if_statement"
        | "for_statement"
        | "foreach_statement"
        | "while_statement"
        | "do_statement"
        | "catch_clause"
        | "conditional_expression"
        | "coalescing_expression"
        | "case" => decisions += 1,
        "binary_expression" => {
            if matches!(binary_operator(node, source), "&&" | "||" | "??") {
                decisions += 1;
            }
        }
        _ => {}
    });
    decisions
}

/// csharpsquid:S1541 — a function's cyclomatic complexity stays within the
/// threshold.
fn check_cyclomatic_complexity(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for function in collect_kinds(root, &CALLABLE_BODY_OWNER_KINDS) {
        if is_error_tainted(function) {
            continue;
        }
        let Some(body) = body_of(function) else {
            continue;
        };
        let complexity = 1 + cyclomatic_decisions(body, source);
        if complexity > options.maximum_function_complexity_threshold {
            issues.push(issue(
                language,
                "S1541",
                format!(
                    "Reduce this function's cyclomatic complexity from {complexity} to at most {}.",
                    options.maximum_function_complexity_threshold
                ),
                range_of(name_anchor(function)),
            ));
        }
    }
    issues
}

/// Simplified S3776 cognitive score: structural keywords weigh one plus
/// their nesting depth, boolean operators and jumps weigh one each.
fn cognitive_complexity(node: Node<'_>, nesting: u32, source: &str) -> u32 {
    let mut score = 0_u32;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let kind = child.kind();
        if matches!(
            kind,
            "if_statement"
                | "for_statement"
                | "foreach_statement"
                | "while_statement"
                | "do_statement"
                | "switch_statement"
                | "catch_clause"
                | "conditional_expression"
        ) {
            score += 1 + nesting;
            score += cognitive_complexity(child, nesting + 1, source);
        } else {
            match kind {
                "case" | "goto_statement" | "break_statement" | "continue_statement" => {
                    score += 1;
                }
                "binary_expression" => {
                    if matches!(binary_operator(child, source), "&&" | "||") {
                        score += 1;
                    }
                }
                _ => {}
            }
            score += cognitive_complexity(child, nesting, source);
        }
    }
    score
}

/// csharpsquid:S3776 — cognitive complexity stays within the thresholds;
/// accessors use the smaller `propertyThreshold`.
fn check_cognitive_complexity(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for function in collect_kinds(root, &CALLABLE_BODY_OWNER_KINDS) {
        if is_error_tainted(function) {
            continue;
        }
        let Some(body) = body_of(function) else {
            continue;
        };
        let threshold = if function.kind() == "accessor_declaration" {
            options.maximum_accessor_complexity_threshold
        } else {
            options.maximum_cognitive_complexity_threshold
        };
        let score = cognitive_complexity(body, 0, source);
        if score > threshold {
            issues.push(issue(
                language,
                "S3776",
                format!(
                    "Reduce this function's cognitive complexity from {score} to at most {threshold}."
                ),
                range_of(name_anchor(function)),
            ));
        }
    }
    issues
}

/// Logical-operator occurrences within an expression subtree.
fn logical_operator_count(expression: Node<'_>, source: &str) -> u32 {
    to_u32(
        collect_kinds(expression, &["binary_expression"])
            .iter()
            .filter(|operand| matches!(binary_operator(**operand, source), "&&" | "||"))
            .count(),
    )
}

/// csharpsquid:S1067 — one expression chains at most the tolerated number
/// of logical operators.
fn check_logical_operator_counts(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(expression)
            || !matches!(binary_operator(expression, source), "&&" | "||")
        {
            continue;
        }
        let parent_is_logical_chain = expression.parent().is_some_and(|parent| {
            parent.kind() == "binary_expression"
                && matches!(binary_operator(parent, source), "&&" | "||")
        });
        if parent_is_logical_chain {
            continue;
        }
        let count = logical_operator_count(expression, source);
        if count > options.maximum_logical_operators {
            issues.push(issue(
                language,
                "S1067",
                format!(
                    "Reduce the number of logical operators ({count} > {}).",
                    options.maximum_logical_operators
                ),
                range_of(expression),
            ));
        }
    }
    issues
}

/// csharpsquid:S1186 — methods, constructors, and operators are not left
/// empty. Attributed members (framework hooks, externals, stubs under test
/// markers) stay untouched.
fn check_empty_methods(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const KINDS: [&str; 3] = [
        "method_declaration",
        "constructor_declaration",
        "operator_declaration",
    ];
    const KIND_WORDS: [(&str, &str); 3] = [
        ("method_declaration", "method"),
        ("constructor_declaration", "constructor"),
        ("operator_declaration", "operator"),
    ];
    let mut issues = Vec::new();
    for member in collect_kinds(root, &KINDS) {
        if is_error_tainted(member) || is_attributed(member, source) {
            continue;
        }
        let Some(body) = body_of(member) else {
            continue;
        };
        let mut cursor = body.walk();
        if body.children(&mut cursor).any(|child| child.is_named()) {
            continue;
        }
        let word = KIND_WORDS
            .iter()
            .find(|(kind, _)| *kind == member.kind())
            .map_or("member", |(_, word)| word);
        issues.push(issue(
            language,
            "S1186",
            format!("Remove this empty {word} or add its implementation."),
            range_of(name_anchor(member)),
        ));
    }
    issues
}

/// csharpsquid:S1048 — finalizers do not throw.
fn check_finalizer_throws(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for destructor in collect_kinds(root, &["destructor_declaration"]) {
        if is_error_tainted(destructor) {
            continue;
        }
        let Some(body) = body_of(destructor) else {
            continue;
        };
        if subtree_contains_kind(body, "throw_statement") {
            issues.push(issue(
                language,
                "S1048",
                "A finalizer must not throw exceptions.",
                range_of(destructor),
            ));
        }
    }
    issues
}

/// csharpsquid:S3880 — finalizers either work or disappear.
fn check_empty_finalizers(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for destructor in collect_kinds(root, &["destructor_declaration"]) {
        if is_error_tainted(destructor) {
            continue;
        }
        let Some(body) = body_of(destructor) else {
            continue;
        };
        let mut cursor = body.walk();
        if !body.children(&mut cursor).any(|child| child.is_named()) {
            issues.push(issue(
                language,
                "S3880",
                "Remove this empty finalizer.",
                range_of(destructor),
            ));
        }
    }
    issues
}

/// Accessors of a property's accessor list, source order.
fn accessors_of(property: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = property.walk();
    property
        .children(&mut cursor)
        .find(|child| child.kind() == "accessor_list")
        .map(|list| {
            let mut list_cursor = list.walk();
            list.children(&mut list_cursor)
                .filter(|accessor| accessor.kind() == "accessor_declaration")
                .collect()
        })
        .unwrap_or_default()
}

/// An accessor's keyword (`get`, `set`, ...).
fn accessor_keyword<'a>(accessor: Node<'_>, source: &'a str) -> &'a str {
    let mut cursor = accessor.walk();
    accessor
        .children(&mut cursor)
        .find(|child| !child.is_named())
        .map_or("", |token| node_text(token, source))
}

/// csharpsquid:S2372 — property getters do not throw.
fn check_property_getter_throws(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for property in collect_kinds(root, &["property_declaration"]) {
        if is_error_tainted(property) {
            continue;
        }
        for accessor in accessors_of(property) {
            if accessor_keyword(accessor, source) != "get" {
                continue;
            }
            let throws = body_of(accessor)
                .is_some_and(|body| subtree_contains_kind(body, "throw_statement"));
            if throws {
                issues.push(issue(
                    language,
                    "S2372",
                    "A property getter must not throw exceptions.",
                    range_of(accessor),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S2376 — write-only properties hide their intent.
fn check_write_only_properties(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for property in collect_kinds(root, &["property_declaration"]) {
        if is_error_tainted(property) || accessors_of(property).is_empty() {
            continue;
        }
        let has_getter = accessors_of(property)
            .iter()
            .any(|accessor| accessor_keyword(*accessor, source) == "get");
        if !has_getter {
            issues.push(issue(
                language,
                "S2376",
                "Add a getter to this write-only property.",
                range_of(name_anchor(property)),
            ));
        }
    }
    issues
}

/// The backing identifier a getter yields: a lone `return field;` or
/// `=> field;` body. Computed returns (`return field + 1;`) never match.
fn getter_field<'a>(accessor: Node<'_>, source: &'a str) -> Option<&'a str> {
    fn yields_sole_identifier(expression: Node<'_>) -> bool {
        let mut cursor = expression.walk();
        let operands: Vec<Node> = expression
            .children(&mut cursor)
            .filter(tree_sitter::Node::is_named)
            .collect();
        operands.len() == 1 && operands[0].kind() == "identifier"
    }
    let body = body_of(accessor)?;
    let shaped = if body.kind() == "arrow_expression_clause" {
        yields_sole_identifier(body)
    } else if body.kind() == "block" {
        let statements = embedded_bodies(body);
        statements.len() == 1
            && statements[0].kind() == "return_statement"
            && yields_sole_identifier(statements[0])
    } else {
        false
    };
    if !shaped {
        return None;
    }
    let identifiers = collect_kinds(body, &["identifier"]);
    (identifiers.len() == 1).then(|| node_text(identifiers[0], source))
}

/// The backing identifier a setter stores into: a single `field = value;`
/// or `=> field = value;` body.
fn setter_field<'a>(accessor: Node<'_>, source: &'a str) -> Option<&'a str> {
    let body = body_of(accessor)?;
    let assignments = collect_kinds(body, &["assignment_expression"]);
    let assignment = assignments.first()?;
    let identifiers = collect_kinds(*assignment, &["identifier"]);
    if assignments.len() != 1
        || identifiers.len() != 2
        || binary_operator(*assignment, source) != "="
        || node_text(identifiers[1], source) != "value"
    {
        return None;
    }
    Some(node_text(identifiers[0], source))
}

/// csharpsquid:S2292 — trivial getter/setter pairs become auto-properties.
fn check_trivial_properties(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for property in collect_kinds(root, &["property_declaration"]) {
        if is_error_tainted(property) {
            continue;
        }
        let accessors = accessors_of(property);
        let reads_backing_field = accessors.iter().any(|accessor| {
            accessor_keyword(*accessor, source) == "get"
                && getter_field(*accessor, source).is_some()
        });
        let writes_backing_field = accessors.iter().any(|accessor| {
            accessor_keyword(*accessor, source) == "set"
                && setter_field(*accessor, source).is_some()
        });
        if reads_backing_field && writes_backing_field && accessors.len() == 2 {
            issues.push(issue(
                language,
                "S2292",
                "Replace this trivial property with an auto-implemented one.",
                range_of(name_anchor(property)),
            ));
        }
    }
    issues
}

/// csharpsquid:S1694 — abstract classes mix abstract with concrete members.
fn check_abstract_member_mix(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_declaration in collect_kinds(root, &["class_declaration"]) {
        if is_error_tainted(class_declaration)
            || !has_modifier(&modifiers_of(class_declaration, source), "abstract")
        {
            continue;
        }
        let mut abstract_members = 0_usize;
        let mut concrete_members = 0_usize;
        for member in type_members(class_declaration) {
            if !matches!(member.kind(), "method_declaration" | "property_declaration") {
                continue;
            }
            if has_modifier(&modifiers_of(member, source), "abstract") {
                abstract_members += 1;
            } else {
                concrete_members += 1;
            }
        }
        if abstract_members == 0 || concrete_members == 0 {
            issues.push(issue(
                language,
                "S1694",
                "Make this abstract class declare both abstract and concrete members.",
                range_of(name_anchor(class_declaration)),
            ));
        }
    }
    issues
}

/// Whether a type's declaration list carries no member declarations; the
/// raw member list includes the anonymous braces.
fn type_has_no_members(type_node: Node<'_>) -> bool {
    type_members(type_node)
        .iter()
        .all(|member| !member.is_named())
}

/// csharpsquid:S2094 — classes and records carry members.
fn check_empty_classes_and_records(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    const KINDS: [&str; 2] = ["class_declaration", "record_declaration"];
    let mut issues = Vec::new();
    for type_declaration in collect_kinds(root, &KINDS) {
        let positional_record = type_declaration.kind() == "record_declaration"
            && type_declaration
                .children(&mut type_declaration.walk())
                .any(|child| child.kind() == "parameter_list");
        if is_error_tainted(type_declaration)
            || has_modifier(&modifiers_of(type_declaration, source), "partial")
            || positional_record
        {
            continue;
        }
        if type_has_no_members(type_declaration) {
            issues.push(issue(
                language,
                "S2094",
                format!(
                    "Add members to this {} or remove it.",
                    declaration_kind_word(type_declaration.kind())
                ),
                range_of(name_anchor(type_declaration)),
            ));
        }
    }
    issues
}

/// csharpsquid:S4023 — interfaces carry members.
fn check_empty_interfaces(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for interface in collect_kinds(root, &["interface_declaration"]) {
        if is_error_tainted(interface) || has_modifier(&modifiers_of(interface, source), "partial")
        {
            continue;
        }
        if type_has_no_members(interface) {
            issues.push(issue(
                language,
                "S4023",
                "Add members to this interface or remove it.",
                range_of(name_anchor(interface)),
            ));
        }
    }
    issues
}

/// csharpsquid:S3261 — namespaces group declarations.
fn check_empty_namespaces(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for namespace in collect_kinds(root, &["namespace_declaration"]) {
        if is_error_tainted(namespace) {
            continue;
        }
        let mut cursor = namespace.walk();
        let has_members = namespace
            .children(&mut cursor)
            .find(|child| child.kind() == "declaration_list")
            .is_some_and(|list| {
                let mut list_cursor = list.walk();
                list.children(&mut list_cursor)
                    .any(|member| member.is_named())
            });
        if !has_members {
            issues.push(issue(
                language,
                "S3261",
                "Remove this empty namespace or populate it.",
                range_of(namespace),
            ));
        }
    }
    issues
}

/// csharpsquid:S3903 — types live in named namespaces. A compilation unit
/// holding a single type stays untouched: a lone top-level type is a
/// common, deliberate layout.
fn check_types_outside_namespaces(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let file_scope_types: Vec<Node> = collect_kinds(root, &TYPE_DECLARATION_KINDS)
        .into_iter()
        .filter(|type_declaration| {
            type_declaration
                .parent()
                .is_some_and(|parent| parent.kind() == "compilation_unit")
        })
        .collect();
    if file_scope_types.len() < 2 {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for type_declaration in file_scope_types {
        if is_error_tainted(type_declaration) {
            continue;
        }
        issues.push(issue(
            language,
            "S3903",
            format!(
                "Move this {} into a namespace.",
                declaration_kind_word(type_declaration.kind())
            ),
            range_of(name_anchor(type_declaration)),
        ));
    }
    issues
}

// ---------------------------------------------------------------------------
// A5 — shadowing, assignment placement, simple expression patterns
// ---------------------------------------------------------------------------

/// The operator token of a binary or assignment expression. Anonymous
/// tokens carry their spelling as node kind, so no source text is needed.
fn operator_of(expression: Node<'_>) -> Option<&'static str> {
    const OPERATORS: [&str; 23] = [
        "==", "!=", "<", ">", "<=", ">=", "&&", "||", "??", "+", "-", "*", "/", "%", "&", "|", "^",
        "<<", ">>", ">>>", "=", "+=", "-=",
    ];
    let mut cursor = expression.walk();
    let kind = expression
        .children(&mut cursor)
        .find(|child| !child.is_named())?
        .kind();
    OPERATORS
        .iter()
        .find(|operator| **operator == kind)
        .copied()
}

/// The two operand expressions of a binary or assignment expression.
fn binary_operands<'t>(expression: Node<'t>) -> Option<(Node<'t>, Node<'t>)> {
    let mut cursor = expression.walk();
    let operands: Vec<Node<'t>> = expression
        .children(&mut cursor)
        .filter(tree_sitter::Node::is_named)
        .collect();
    match operands.as_slice() {
        [left, right] => Some((*left, *right)),
        _ => None,
    }
}

/// Comparison expressions as `(expression, left, right)` triples; tainted
/// subtrees are skipped.
fn comparisons(root: Node<'_>) -> Vec<(Node<'_>, Node<'_>, Node<'_>)> {
    collect_kinds(root, &["binary_expression"])
        .into_iter()
        .filter(|expression| !is_error_tainted(*expression))
        .filter_map(|expression| {
            let (left, right) = binary_operands(expression)?;
            matches!(
                operator_of(expression),
                Some("==" | "!=" | "<" | ">" | "<=" | ">=")
            )
            .then_some((expression, left, right))
        })
        .collect()
}

/// The first named child (the sole operand of a prefix unary expression).
fn first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.children(&mut cursor).find(tree_sitter::Node::is_named)
}

/// The plain identifier an expression denotes: identifiers themselves and
/// the member name of a member access (`x.Count` → `Count`).
fn expression_name<'a>(expression: Node<'_>, source: &'a str) -> Option<&'a str> {
    match expression.kind() {
        "identifier" => Some(node_text(expression, source)),
        "member_access_expression" => {
            let mut cursor = expression.walk();
            let named: Vec<Node> = expression
                .children(&mut cursor)
                .filter(tree_sitter::Node::is_named)
                .collect();
            let last = named.last()?;
            (last.kind() == "identifier").then(|| node_text(*last, source))
        }
        _ => None,
    }
}

/// Whether the operand is the literal `0`.
fn is_zero_literal(operand: Node<'_>, source: &str) -> bool {
    operand.kind() == "integer_literal" && node_text(operand, source) == "0"
}

/// `-1`: a negated unit literal.
fn is_negative_one(operand: Node<'_>, source: &str) -> bool {
    operand.kind() == "prefix_unary_expression"
        && operator_of(operand) == Some("-")
        && first_named_child(operand).is_some_and(|literal| node_text(literal, source) == "1")
}

/// Parses an integer literal's decimal or hexadecimal value.
fn integer_literal_value(literal_text: &str) -> Option<u64> {
    let trimmed = literal_text.trim_end_matches(['u', 'U', 'l', 'L']);
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        let cleaned: String = hex.chars().filter(char::is_ascii_hexdigit).collect();
        return u64::from_str_radix(&cleaned, 16).ok();
    }
    if !trimmed.chars().all(|c| c.is_ascii_digit() || c == '_') {
        return None;
    }
    trimmed
        .chars()
        .filter(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .ok()
}

/// Names of fields and properties declared directly by a type.
fn field_and_property_names(
    type_declaration: Node<'_>,
    source: &str,
) -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();
    for member in type_members(type_declaration) {
        match member.kind() {
            "field_declaration" | "event_field_declaration" => {
                for declarator in collect_kinds(member, &["variable_declarator"]) {
                    if let Some(identifier) = first_named_child(declarator)
                        && identifier.kind() == "identifier"
                    {
                        names.insert(node_text(identifier, source).to_string());
                    }
                }
            }
            "property_declaration" => {
                if let Some(name) = member.child_by_field_name("name") {
                    names.insert(node_text(name, source).to_string());
                }
            }
            _ => {}
        }
    }
    names
}

/// csharpsquid:S1117 — locals do not shadow fields or properties of their
/// enclosing type.
fn check_local_shadowing(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_declaration in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if is_error_tainted(type_declaration) {
            continue;
        }
        let member_names = field_and_property_names(type_declaration, source);
        if member_names.is_empty() {
            continue;
        }
        for local in collect_kinds(type_declaration, &["local_declaration_statement"]) {
            for declarator in collect_kinds(local, &["variable_declarator"]) {
                let Some(identifier) = first_named_child(declarator) else {
                    continue;
                };
                if identifier.kind() != "identifier" {
                    continue;
                }
                let name = node_text(identifier, source);
                if member_names.contains(name) {
                    issues.push(issue(
                        language,
                        "S1117",
                        format!("Rename '{name}'; it shadows a member of its enclosing type."),
                        range_of(declarator),
                    ));
                }
            }
        }
    }
    issues
}

/// csharpsquid:S1121 — assignments belong in dedicated statements.
fn check_assignments_in_expressions(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for assignment in collect_kinds(root, &["assignment_expression"]) {
        if is_error_tainted(assignment) {
            continue;
        }
        let parent_kind = assignment.parent().map(|parent| parent.kind());
        if matches!(parent_kind, Some("expression_statement" | "for_statement")) {
            continue;
        }
        issues.push(issue(
            language,
            "S1121",
            "Assign this value in a dedicated statement.",
            range_of(assignment),
        ));
    }
    issues
}

/// csharpsquid:S881 — increments and decrements stay standalone.
fn check_embedded_increments(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    const KINDS: [&str; 2] = ["prefix_unary_expression", "postfix_unary_expression"];
    let mut issues = Vec::new();
    for unary in collect_kinds(root, &KINDS) {
        if is_error_tainted(unary) || !matches!(operator_of(unary), Some("++" | "--")) {
            continue;
        }
        let parent_kind = unary.parent().map(|parent| parent.kind());
        if matches!(parent_kind, Some("expression_statement" | "for_statement")) {
            continue;
        }
        issues.push(issue(
            language,
            "S881",
            "Extract this increment or decrement into its own statement.",
            range_of(unary),
        ));
    }
    issues
}

/// csharpsquid:S1656 — nothing assigns an expression to itself.
fn check_self_assignments(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for assignment in collect_kinds(root, &["assignment_expression"]) {
        if is_error_tainted(assignment) || operator_of(assignment) != Some("=") {
            continue;
        }
        let Some((left, right)) = binary_operands(assignment) else {
            continue;
        };
        if node_text(left, source).trim() == node_text(right, source).trim() {
            issues.push(issue(
                language,
                "S1656",
                "Remove this self-assignment.",
                range_of(assignment),
            ));
        }
    }
    issues
}

/// Boolean-literal value on either side of a comparison, if present.
fn boolean_literal_side(left: Node<'_>, right: Node<'_>, source: &str) -> Option<bool> {
    for operand in [left, right] {
        if operand.kind() == "boolean_literal" {
            return Some(node_text(operand, source) == "true");
        }
    }
    None
}

/// csharpsquid:S1125 — identity comparisons against boolean literals drop
/// the literal.
fn check_redundant_boolean_comparisons(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (expression, left, right) in comparisons(root) {
        let literal = boolean_literal_side(left, right, source);
        let redundant = matches!(
            (operator_of(expression), literal),
            (Some("=="), Some(true)) | (Some("!="), Some(false))
        );
        if redundant {
            issues.push(issue(
                language,
                "S1125",
                "Remove the redundant boolean literal from this comparison.",
                range_of(expression),
            ));
        }
    }
    issues
}

/// csharpsquid:S3240 — conditions use their simplest shape: negation beats
/// comparing against `false`, ternaries over boolean literals collapse to
/// their condition.
fn check_simplifiable_conditions(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (expression, left, right) in comparisons(root) {
        let literal = boolean_literal_side(left, right, source);
        let simplifiable = matches!(
            (operator_of(expression), literal),
            (Some("=="), Some(false)) | (Some("!="), Some(true))
        );
        if simplifiable {
            issues.push(issue(
                language,
                "S3240",
                "Replace this comparison with a negation of its operand.",
                range_of(expression),
            ));
        }
    }
    for conditional in collect_kinds(root, &["conditional_expression"]) {
        if is_error_tainted(conditional) {
            continue;
        }
        let mut cursor = conditional.walk();
        let branches: Vec<Node> = conditional
            .children(&mut cursor)
            .filter(tree_sitter::Node::is_named)
            .skip(1)
            .collect();
        if branches.len() == 2 && branches.iter().all(|b| b.kind() == "boolean_literal") {
            issues.push(issue(
                language,
                "S3240",
                "Replace this ternary with its condition directly.",
                range_of(conditional),
            ));
        }
    }
    issues
}

/// csharpsquid:S1940 — negated equality flips into the opposite operator.
fn check_inverted_boolean_checks(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for unary in collect_kinds(root, &["prefix_unary_expression"]) {
        if is_error_tainted(unary) || operator_of(unary) != Some("!") {
            continue;
        }
        let invertible = first_named_child(unary).is_some_and(|operand| {
            operand.kind() == "parenthesized_expression"
                && first_named_child(operand).is_some_and(|inner| {
                    inner.kind() == "binary_expression"
                        && matches!(operator_of(inner), Some("==" | "!="))
                })
        });
        if invertible {
            issues.push(issue(
                language,
                "S1940",
                "Invert this comparison instead of negating it.",
                range_of(unary),
            ));
        }
    }
    issues
}

/// csharpsquid:S2761 — prefix operators do not double up.
fn check_doubled_prefix_operators(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for unary in collect_kinds(root, &["prefix_unary_expression"]) {
        if is_error_tainted(unary) || !matches!(operator_of(unary), Some("!" | "~" | "+" | "-")) {
            continue;
        }
        let doubled = first_named_child(unary).is_some_and(|operand| {
            operand.kind() == "prefix_unary_expression"
                && matches!(operator_of(operand), Some("!" | "~" | "+" | "-"))
        });
        if doubled {
            issues.push(issue(
                language,
                "S2761",
                "Collapse these doubled prefix operators.",
                range_of(unary),
            ));
        }
    }
    issues
}

/// csharpsquid:S2688 — NaN compares unequal to everything, itself included.
fn check_nan_comparisons(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (expression, left, right) in comparisons(root) {
        if !matches!(operator_of(expression), Some("==" | "!=")) {
            continue;
        }
        let names_nan = [left, right]
            .iter()
            .any(|operand| expression_name(*operand, source) == Some("NaN"));
        if names_nan {
            issues.push(issue(
                language,
                "S2688",
                "Use 'IsNaN' to test for NaN; equality comparisons never hold.",
                range_of(expression),
            ));
        }
    }
    issues
}

/// csharpsquid:S1244 — floating-point equality needs a tolerance.
fn check_float_equality(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (expression, left, right) in comparisons(root) {
        let float_side = left.kind() == "real_literal" || right.kind() == "real_literal";
        if matches!(operator_of(expression), Some("==" | "!=")) && float_side {
            issues.push(issue(
                language,
                "S1244",
                "Compare floating-point values with a tolerance instead of equality.",
                range_of(expression),
            ));
        }
    }
    issues
}

/// csharpsquid:S2198 — relational self-comparisons are always constant.
fn check_self_relational_comparisons(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (expression, left, right) in comparisons(root) {
        if !matches!(operator_of(expression), Some("<" | ">" | "<=" | ">=")) {
            continue;
        }
        if node_text(left, source).trim() == node_text(right, source).trim() {
            issues.push(issue(
                language,
                "S2198",
                "Remove this contradictory comparison of an expression with itself.",
                range_of(expression),
            ));
        }
    }
    issues
}

/// Collection-count member tails (`Count`, `Length`).
fn count_member_tail(operand: Node<'_>, source: &str) -> bool {
    matches!(expression_name(operand, source), Some("Count" | "Length"))
}

/// csharpsquid:S3981 — collection sizes never compare against negatives.
fn check_negative_size_comparisons(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    fn negative_value(operand: Node<'_>, source: &str) -> Option<i64> {
        if operand.kind() != "prefix_unary_expression" || operator_of(operand) != Some("-") {
            return None;
        }
        let literal = first_named_child(operand)?;
        integer_literal_value(node_text(literal, source))
            .and_then(|value| i64::try_from(value).ok())
            .map(|value| -value)
    }
    let mut issues = Vec::new();
    for (expression, left, right) in comparisons(root) {
        let size_side = [left, right].iter().any(|o| count_member_tail(*o, source));
        let negative_side = [left, right]
            .iter()
            .any(|o| negative_value(*o, source).is_some());
        if size_side && negative_side {
            issues.push(issue(
                language,
                "S3981",
                "Collection sizes are never negative; fix this comparison.",
                range_of(expression),
            ));
        }
    }
    issues
}

/// csharpsquid:S2692 — '`IndexOf`' presence tests use '>=' not '>'.
fn check_indexof_positive_checks(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    fn indexof_call(operand: Node<'_>, source: &str) -> bool {
        operand.kind() == "invocation_expression"
            && first_named_child(operand).is_some_and(|callee| {
                callee.kind() == "member_access_expression"
                    && matches!(
                        expression_name(callee, source),
                        Some("IndexOf" | "LastIndexOf")
                    )
            })
    }
    let mut issues = Vec::new();
    for (expression, left, right) in comparisons(root) {
        let pattern = operator_of(expression) == Some(">")
            && ((indexof_call(left, source) && is_zero_literal(right, source))
                || (indexof_call(right, source) && is_zero_literal(left, source)));
        if pattern {
            issues.push(issue(
                language,
                "S2692",
                "Test 'IndexOf' results with '>= 0'; '>' wrongly rejects index 0.",
                range_of(expression),
            ));
        }
    }
    issues
}

/// csharpsquid:S2183 — shift amounts stay within 1..31 for 32-bit operands.
fn check_shift_amounts(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(expression)
            || !matches!(operator_of(expression), Some("<<" | ">>" | ">>>"))
        {
            continue;
        }
        let Some((_, right)) = binary_operands(expression) else {
            continue;
        };
        if right.kind() != "integer_literal" {
            continue;
        }
        let Some(amount) = integer_literal_value(node_text(right, source)) else {
            continue;
        };
        if amount == 0 || amount >= 32 {
            issues.push(issue(
                language,
                "S2183",
                format!(
                    "Shift by a non-zero amount below the operand width ({amount} is out of range)."
                ),
                range_of(expression),
            ));
        }
    }
    issues
}

/// csharpsquid:S2437 — bit operations fold away when an operand makes them
/// constants.
fn check_unnecessary_bit_operations(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(expression) {
            continue;
        }
        let Some((left, right)) = binary_operands(expression) else {
            continue;
        };
        let zero_on_either = is_zero_literal(left, source) || is_zero_literal(right, source);
        let minus_one_on_either = is_negative_one(left, source) || is_negative_one(right, source);
        let identical = node_text(left, source).trim() == node_text(right, source).trim();
        let verdict = match operator_of(expression) {
            Some("&") if zero_on_either => Some("'and' with zero always yields zero."),
            Some("|") if minus_one_on_either => Some("'or' with -1 always yields -1."),
            Some("|") if zero_on_either => Some("'or' with zero changes nothing."),
            Some("^") if identical => Some("'xor' of identical operands always yields zero."),
            _ => None,
        };
        if let Some(verdict) = verdict {
            issues.push(issue(
                language,
                "S2437",
                format!("Remove this unnecessary bit operation: {verdict}"),
                range_of(expression),
            ));
        }
    }
    issues
}

/// csharpsquid:S2197 — remainders compare against ranges, not values.
fn check_modulus_equality(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    fn modulus(operand: Node<'_>) -> bool {
        operand.kind() == "binary_expression" && operator_of(operand) == Some("%")
    }
    let mut issues = Vec::new();
    for (expression, left, right) in comparisons(root) {
        if matches!(operator_of(expression), Some("==" | "!=")) && (modulus(left) || modulus(right))
        {
            issues.push(issue(
                language,
                "S2197",
                "Compare remainder results against ranges, not single values.",
                range_of(expression),
            ));
        }
    }
    issues
}

/// csharpsquid:S3358 — ternaries do not nest.
fn check_nested_ternaries(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for conditional in collect_kinds(root, &["conditional_expression"]) {
        if !is_error_tainted(conditional)
            && has_ancestor_with_kind(conditional, &["conditional_expression"])
        {
            issues.push(issue(
                language,
                "S3358",
                "Extract this nested ternary into its own statement.",
                range_of(conditional),
            ));
        }
    }
    issues
}

/// csharpsquid:S3060 — 'this' does not take part in 'is' type tests.
fn check_this_is_checks(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for is_expression in collect_kinds(root, &["is_expression"]) {
        if is_error_tainted(is_expression) {
            continue;
        }
        let tests_this = first_named_child(is_expression)
            .is_some_and(|operand| node_text(operand, source) == "this");
        if tests_this {
            issues.push(issue(
                language,
                "S3060",
                "Do not combine 'this' with the 'is' operator.",
                range_of(is_expression),
            ));
        }
    }
    issues
}

/// csharpsquid:S4201 — null checks merge into 'is' patterns.
fn check_null_check_with_is(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    fn is_pattern_name<'a>(operand: Node<'_>, source: &'a str) -> Option<&'a str> {
        if operand.kind() != "is_expression" {
            return None;
        }
        first_named_child(operand)
            .filter(|target| target.kind() == "identifier")
            .and_then(|target| expression_name(target, source))
    }
    let mut issues = Vec::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(expression) || operator_of(expression) != Some("&&") {
            continue;
        }
        let Some((left, right)) = binary_operands(expression) else {
            continue;
        };
        let redundant = [
            (
                null_check_name(left, source),
                is_pattern_name(right, source),
            ),
            (
                null_check_name(right, source),
                is_pattern_name(left, source),
            ),
        ]
        .iter()
        .any(|(null_name, pattern)| null_name.is_some() && *null_name == *pattern);
        if redundant {
            issues.push(issue(
                language,
                "S4201",
                "Drop the null check; the 'is' type test already rejects null.",
                range_of(expression),
            ));
        }
    }
    issues
}

/// Zero-argument `GetType()` invocation.
fn gettype_invocation(operand: Node<'_>, source: &str) -> bool {
    if operand.kind() != "invocation_expression" {
        return false;
    }
    let Some(callee) = first_named_child(operand) else {
        return false;
    };
    callee.kind() == "member_access_expression"
        && expression_name(callee, source) == Some("GetType")
        && collect_kinds(operand, &["argument_list"])
            .iter()
            .all(|list| list.named_child_count() == 0)
}

/// csharpsquid:S2219 — GetType()/typeof(X) pairs become 'is' patterns.
fn check_gettype_typeof_comparisons(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (expression, left, right) in comparisons(root) {
        if !matches!(operator_of(expression), Some("==" | "!=")) {
            continue;
        }
        let pattern = (gettype_invocation(left, source) && right.kind() == "typeof_expression")
            || (gettype_invocation(right, source) && left.kind() == "typeof_expression");
        if pattern {
            issues.push(issue(
                language,
                "S2219",
                "Use the 'is' type pattern instead of comparing GetType() with typeof().",
                range_of(expression),
            ));
        }
    }
    issues
}

/// The identifier a comparison checks against `null`.
fn null_check_name<'a>(comparison: Node<'_>, source: &'a str) -> Option<&'a str> {
    if !matches!(operator_of(comparison), Some("==")) {
        return None;
    }
    let (left, right) = binary_operands(comparison)?;
    if left.kind() == "null_literal" {
        return expression_name(right, source);
    }
    if right.kind() == "null_literal" {
        return expression_name(left, source);
    }
    None
}

/// The identifier an empty-string test inspects, when the operand is one
/// (`s == ""`, `s == string.Empty`, and `s.Length == 0` shapes alike).
fn empty_check_name<'a>(comparison: Node<'_>, source: &'a str) -> Option<&'a str> {
    if !matches!(operator_of(comparison), Some("==")) {
        return None;
    }
    let (left, right) = binary_operands(comparison)?;
    for (tested, expected) in [(left, right), (right, left)] {
        let name = match tested.kind() {
            "identifier" => expression_name(tested, source),
            "member_access_expression" => {
                if expression_name(tested, source) == Some("Length") {
                    first_named_child(tested).and_then(|target| expression_name(target, source))
                } else {
                    None
                }
            }
            _ => continue,
        }?;
        let is_empty_test = match expected.kind() {
            "string_literal" => node_text(expected, source) == "\"\"",
            "member_access_expression" => expression_name(expected, source) == Some("Empty"),
            "integer_literal" => is_zero_literal(expected, source),
            _ => false,
        };
        if is_empty_test {
            return Some(name);
        }
    }
    None
}

/// csharpsquid:S3256 — compound null-and-empty checks collapse into
/// 'string.IsNullOrEmpty'.
fn check_null_or_empty_patterns(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(expression) || operator_of(expression) != Some("||") {
            continue;
        }
        let Some((left, right)) = binary_operands(expression) else {
            continue;
        };
        let collapsible = [
            (
                null_check_name(left, source),
                empty_check_name(right, source),
            ),
            (
                null_check_name(right, source),
                empty_check_name(left, source),
            ),
        ]
        .iter()
        .any(|(null_name, empty_name)| null_name.is_some() && *null_name == *empty_name);
        if collapsible {
            issues.push(issue(
                language,
                "S3256",
                "Replace this compound check with 'string.IsNullOrEmpty'.",
                range_of(expression),
            ));
        }
    }
    issues
}
// ---------------------------------------------------------------------------
// Shared expression helpers (Tier A6–A8)
// ---------------------------------------------------------------------------

/// Loop headers wrapping a body statement.
const LOOP_KINDS: [&str; 4] = [
    "for_statement",
    "foreach_statement",
    "while_statement",
    "do_statement",
];

/// Attribute spellings that mark a method as part of a test suite.
const TEST_ATTRIBUTE_NAMES: [&str; 10] = [
    "Test",
    "Fact",
    "Theory",
    "TestCase",
    "TestMethod",
    "TestInitialize",
    "TestCleanup",
    "SetUp",
    "TearDown",
    "OneTimeSetUp",
];

/// Statements directly inside a plain block.
fn block_statements(block: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = block.walk();
    block
        .children(&mut cursor)
        .filter(|child| child.is_named() && is_statement_kind(child.kind()))
        .collect()
}

/// Whether a declaration carries a test-suite attribute.
fn is_test_attributed(declaration: Node<'_>, source: &str) -> bool {
    attributes_of(declaration, source)
        .iter()
        .any(|name| TEST_ATTRIBUTE_NAMES.contains(name))
}

/// The nearest enclosing type declaration, if any.
fn enclosing_type(node: Node<'_>) -> Option<Node<'_>> {
    ancestors_of(node).find(|ancestor| TYPE_DECLARATION_KINDS.contains(&ancestor.kind()))
}

/// The function expression of an invocation (`f` of `f(args)`).
fn invocation_function(invocation: Node<'_>) -> Option<Node<'_>> {
    first_named_child(invocation)
}

/// Method name an invocation calls (`x.Where(...)` calls `Where`).
fn callee_name<'a>(invocation: Node<'_>, source: &'a str) -> Option<&'a str> {
    expression_name(invocation_function(invocation)?, source)
}

/// Receiver expression of an invocation (`r` of `r.M(args)`).
fn invocation_receiver(invocation: Node<'_>) -> Option<Node<'_>> {
    let function = invocation_function(invocation)?;
    (function.kind() == "member_access_expression").then_some(function)?;
    first_named_child(function)
}

/// Arguments of an invocation's own argument list (nested calls excluded).
fn invocation_arguments(invocation: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = invocation.walk();
    invocation
        .children(&mut cursor)
        .find(|child| child.kind() == "argument_list")
        .map(|list| {
            let mut inner = list.walk();
            list.children(&mut inner)
                .filter(tree_sitter::Node::is_named)
                .collect()
        })
        .unwrap_or_default()
}

/// Whether any call further down the receiver chain satisfies `matches`.
fn receiver_chain_matches(
    invocation: Node<'_>,
    source: &str,
    matches: impl Fn(&str) -> bool,
) -> bool {
    let mut current = invocation_receiver(invocation);
    while let Some(receiver) = current {
        match receiver.kind() {
            "invocation_expression" => {
                if callee_name(receiver, source).is_some_and(&matches) {
                    return true;
                }
                current = invocation_receiver(receiver);
            }
            _ => break,
        }
    }
    false
}

/// Member accesses reading one of `tails` off an owner whose qualified
/// spelling ends with `owner` (`System.GC.Collect` matches owner `GC`).
fn banned_member_accesses<'t>(
    root: Node<'t>,
    source: &str,
    owner: &str,
    tails: &[&str],
) -> Vec<Node<'t>> {
    collect_kinds(root, &["member_access_expression"])
        .into_iter()
        .filter(|node| !is_error_tainted(*node))
        .filter(|node| {
            tails.contains(&expression_name(*node, source).unwrap_or(""))
                && first_named_child(*node)
                    .is_some_and(|receiver| node_text(receiver, source).trim().ends_with(owner))
        })
        .collect()
}

/// Whether an invocation targets one of `tails`; when `owner` is given the
/// callee must sit on a matching owner, otherwise the callee must be a bare
/// identifier.
fn invocation_targets(
    invocation: Node<'_>,
    source: &str,
    owner: Option<&str>,
    tails: &[&str],
) -> bool {
    let Some(function) = invocation_function(invocation) else {
        return false;
    };
    let Some(name) = expression_name(function, source) else {
        return false;
    };
    if !tails.contains(&name) {
        return false;
    }
    match owner {
        None => function.kind() == "identifier",
        Some(owner) => {
            function.kind() == "member_access_expression"
                && first_named_child(function)
                    .is_some_and(|receiver| node_text(receiver, source).trim().ends_with(owner))
        }
    }
}

/// The type spelling of a `new T(...)` creation.
fn creation_type_text<'a>(creation: Node<'_>, source: &'a str) -> &'a str {
    first_named_child(creation).map_or("", |type_node| node_text(type_node, source))
}

/// Bare `new T(...)` expressions used directly as statements.
fn bare_creations(root: Node<'_>) -> Vec<Node<'_>> {
    collect_kinds(root, &["object_creation_expression"])
        .into_iter()
        .filter(|creation| !is_error_tainted(*creation))
        .filter(|creation| {
            creation
                .parent()
                .is_some_and(|parent| parent.kind() == "expression_statement")
        })
        .collect()
}

/// The operator token of an `operator_declaration` (`==`, `+`, ...).
fn overloaded_operator(declaration: Node<'_>) -> Option<&'static str> {
    const TOKENS: [&str; 15] = [
        "==", "!=", "<", ">", "<=", ">=", "+", "-", "*", "/", "%", "&", "|", "^", "<<",
    ];
    let mut cursor = declaration.walk();
    declaration
        .children(&mut cursor)
        .filter(|child| !child.is_named())
        .find_map(|child| TOKENS.iter().find(|token| **token == child.kind()).copied())
}

/// Names of overridden methods declared directly by a type.
fn overridden_names(type_node: Node<'_>, source: &str) -> std::collections::HashSet<String> {
    member_declarations_of_kind(type_node, "method_declaration")
        .into_iter()
        .filter(|method| has_modifier(&modifiers_of(*method, source), "override"))
        .filter_map(|method| method.child_by_field_name("name"))
        .map(|name| node_text(name, source).to_string())
        .collect()
}

/// Members of a kind declared directly by a type.
fn member_declarations_of_kind<'t>(type_node: Node<'t>, kind: &str) -> Vec<Node<'t>> {
    type_members(type_node)
        .into_iter()
        .filter(|member| member.kind() == kind)
        .collect()
}

/// Names of every method declared directly by a type.
fn declared_method_names(type_node: Node<'_>, source: &str) -> std::collections::HashSet<String> {
    member_declarations_of_kind(type_node, "method_declaration")
        .into_iter()
        .filter_map(|method| method.child_by_field_name("name"))
        .map(|name| node_text(name, source).to_string())
        .collect()
}

/// Operator tokens of every operator overload declared directly by a type.
fn overloaded_operators(type_node: Node<'_>) -> Vec<&'static str> {
    member_declarations_of_kind(type_node, "operator_declaration")
        .into_iter()
        .filter_map(overloaded_operator)
        .collect()
}

/// The first member of a kind carrying `name`, for anchoring issues.
fn member_named<'t>(type_node: Node<'t>, kind: &str, name: &str, source: &str) -> Option<Node<'t>> {
    member_declarations_of_kind(type_node, kind)
        .into_iter()
        .find(|member| {
            member
                .child_by_field_name("name")
                .is_some_and(|member_name| node_text(member_name, source) == name)
        })
}

/// Arity of every constructor declared directly by a type.
fn constructor_arities(type_node: Node<'_>) -> Vec<usize> {
    member_declarations_of_kind(type_node, "constructor_declaration")
        .into_iter()
        .map(|ctor| parameters_of(ctor).len())
        .collect()
}

/// Declarator names of fields declared directly by a type whose fields lack
/// `readonly` (and are not constants).
fn mutable_field_names<'t>(type_node: Node<'t>, source: &'t str) -> Vec<&'t str> {
    member_declarations_of_kind(type_node, "field_declaration")
        .into_iter()
        .filter(|field| {
            let modifiers = modifiers_of(*field, source);
            !has_modifier(&modifiers, "readonly") && !has_modifier(&modifiers, "const")
        })
        .flat_map(|field| collect_kinds(field, &["variable_declarator"]))
        .filter_map(|declarator| first_named_child(declarator))
        .filter_map(|identifier| expression_name(identifier, source))
        .collect()
}

/// Whether `scope` mentions `name` as a bare identifier.
fn references_identifier(scope: Node<'_>, name: &str, source: &str) -> bool {
    collect_kinds(scope, &["identifier"])
        .iter()
        .any(|identifier| node_text(*identifier, source) == name)
}

/// The member name invoked through `base.Member(...)` (`base.Equals(x)` →
/// `Equals`); `None` for other receivers.
fn base_call_name<'a>(invocation: Node<'_>, source: &'a str) -> Option<&'a str> {
    let function = invocation_function(invocation)?;
    if function.kind() != "member_access_expression" {
        return None;
    }
    // `base` is an unnamed keyword token, so the raw first child is needed.
    let mut cursor = function.walk();
    let receiver = function.children(&mut cursor).next()?;
    (node_text(receiver, source).trim() == "base")
        .then(|| expression_name(function, source))
        .flatten()
}

/// `(parameter name, body)` of a single-parameter lambda.
fn lambda_shape<'s>(lambda: Node<'s>, source: &'s str) -> Option<(&'s str, Node<'s>)> {
    let mut cursor = lambda.walk();
    let named: Vec<Node> = lambda
        .children(&mut cursor)
        .filter(tree_sitter::Node::is_named)
        .collect();
    let body = *named.last()?;
    let head = *named.first()?;
    let parameter = match head.kind() {
        // The whole name rides on the `implicit_parameter` node itself.
        "implicit_parameter" => node_text(head, source),
        "parameter_list" => {
            let parameter = first_named_child(head)?;
            let identifiers = collect_kinds(parameter, &["identifier"]);
            identifiers.last().map(|id| node_text(*id, source))?
        }
        _ => return None,
    };
    (named.len() >= 2).then_some((parameter, body))
}

/// Whether any `string`-typed local declares `name` under `scope`.
fn declares_string_local(scope: Node<'_>, name: &str, source: &str) -> bool {
    collect_kinds(scope, &["variable_declaration"])
        .iter()
        .any(|declaration| {
            let typed_string = first_named_child(*declaration)
                .is_some_and(|type_node| node_text(type_node, source) == "string");
            typed_string
                && collect_kinds(*declaration, &["variable_declarator"])
                    .iter()
                    .any(|declarator| {
                        first_named_child(*declarator)
                            .and_then(|identifier| expression_name(identifier, source))
                            == Some(name)
                    })
        })
}

// ---------------------------------------------------------------------------
// A6 — numeric/comparison constant-fold patterns
// ---------------------------------------------------------------------------

/// Operators whose identical operands betray a bug (`a * a` may be intended,
/// `a - a` never is).
const IDENTICAL_OPERAND_OPERATORS: [&str; 7] = ["-", "/", "%", "<", ">", "<=", ">="];

/// csharpsquid:S1764 — identical sub-expressions on both sides of an
/// arithmetic or relational operator.
fn check_identical_operands(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(expression) {
            continue;
        }
        let Some(operator) = operator_of(expression) else {
            continue;
        };
        let Some((left, right)) = binary_operands(expression) else {
            continue;
        };
        if IDENTICAL_OPERAND_OPERATORS.contains(&operator)
            && !node_text(left, source).is_empty()
            && node_text(left, source) == node_text(right, source)
        {
            issues.push(issue(
                language,
                "S1764",
                "Identical sub-expressions are used on both sides of this operator.",
                range_of(expression),
            ));
        }
    }
    issues
}

/// csharpsquid:S1862 — a condition repeats along its if/else-if chain. Each
/// chain reports from its own first `if`.
fn check_repeated_chain_conditions(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for header in collect_kinds(root, &["if_statement"]) {
        if is_error_tainted(header) || is_else_alternative(header) {
            continue;
        }
        let mut seen: Vec<&str> = Vec::new();
        let mut current = Some(header);
        while let Some(if_statement) = current {
            if let Some(condition) =
                first_named_child(if_statement).filter(|condition| !is_error_tainted(*condition))
            {
                let text = node_text(condition, source);
                if seen.contains(&text) {
                    issues.push(issue(
                        language,
                        "S1862",
                        "This condition repeats an earlier check in the same chain.",
                        range_of(condition),
                    ));
                } else {
                    seen.push(text);
                }
            }
            current = else_alternative(if_statement)
                .filter(|alternative| alternative.kind() == "if_statement");
        }
    }
    issues
}

/// Statement text of a branch body; block wrappers are flattened so
/// `{ return 1; }` and `return 1;` compare equal.
fn branch_body_text(body: Node<'_>, source: &str) -> String {
    if body.kind() == "block" {
        block_statements(body)
            .iter()
            .map(|statement| node_text(*statement, source))
            .collect::<Vec<_>>()
            .concat()
    } else {
        node_text(body, source).to_string()
    }
}

/// Branch body texts of a complete if/else-if/else chain, or `None` when the
/// chain lacks a terminal `else` (incomplete coverage).
fn if_chain_branch_texts(header: Node<'_>, source: &str) -> Option<Vec<String>> {
    let mut texts = Vec::new();
    let mut current = Some(header);
    while let Some(if_statement) = current {
        let consequence = *embedded_bodies(if_statement).first()?;
        texts.push(branch_body_text(consequence, source));
        let alternative = else_alternative(if_statement)?;
        if alternative.kind() == "if_statement" {
            current = Some(alternative);
        } else {
            texts.push(branch_body_text(alternative, source));
            current = None;
        }
    }
    Some(texts)
}

/// csharpsquid:S3923 — every branch of a conditional runs the same code.
fn check_identical_branches(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for header in collect_kinds(root, &["if_statement"]) {
        if is_error_tainted(header) || is_else_alternative(header) {
            continue;
        }
        let Some(texts) = if_chain_branch_texts(header, source) else {
            continue;
        };
        let identical = texts.len() >= 2
            && texts.iter().all(|text| !text.is_empty())
            && texts.windows(2).all(|pair| pair[0] == pair[1]);
        if identical {
            issues.push(issue(
                language,
                "S3923",
                "Every branch of this conditional performs the same actions.",
                range_of(header),
            ));
        }
    }
    issues
}

/// Statement-sequence spelling of a switch section, for duplicate checks.
fn section_text(section: Node<'_>, source: &str) -> String {
    section_statements(section)
        .iter()
        .map(|statement| node_text(*statement, source))
        .collect::<Vec<_>>()
        .concat()
}

/// csharpsquid:S1871 — switch sections repeating an earlier section's
/// implementation verbatim.
fn check_duplicate_switch_sections(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for switch_statement in collect_kinds(root, &["switch_statement"]) {
        if is_error_tainted(switch_statement) {
            continue;
        }
        let Some(switch_body) = switch_body_of(switch_statement) else {
            continue;
        };
        let sections = switch_sections_of(switch_body);
        for (index, section) in sections.iter().enumerate() {
            let text = section_text(*section, source);
            if text.is_empty() {
                continue;
            }
            if sections[..index]
                .iter()
                .any(|earlier| section_text(*earlier, source) == text)
            {
                issues.push(issue(
                    language,
                    "S1871",
                    "This branch duplicates the implementation of an earlier one.",
                    range_of(*section),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S4144 — sibling methods sharing one verbatim body; later
/// duplicates are flagged against the first carrier.
fn check_duplicate_sibling_methods(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        let mut seen: Vec<(&str, String)> = Vec::new();
        for method in member_declarations_of_kind(type_node, "method_declaration") {
            if is_error_tainted(method) || is_attributed(method, source) {
                continue;
            }
            let Some(body) = body_of(method) else {
                continue;
            };
            let text = node_text(body, source);
            if text.is_empty() {
                continue;
            }
            let name = method
                .child_by_field_name("name")
                .map_or("", |name| node_text(name, source));
            if let Some((carrier, _)) = seen.iter().find(|(_, earlier)| earlier.as_str() == text) {
                issues.push(issue(
                    language,
                    "S4144",
                    format!("Update this method so it no longer duplicates '{carrier}'."),
                    range_of(method),
                ));
            } else {
                seen.push((name, text.to_string()));
            }
        }
    }
    issues
}

/// csharpsquid:S2760 — adjacent if statements rechecking the same condition.
fn check_repeated_adjacent_conditions(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for block in collect_kinds(root, &["block"]) {
        let statements = block_statements(block);
        for pair in statements.windows(2) {
            let (first, second) = (pair[0], pair[1]);
            if first.kind() != "if_statement" || second.kind() != "if_statement" {
                continue;
            }
            let (Some(first_condition), Some(second_condition)) =
                (first_named_child(first), first_named_child(second))
            else {
                continue;
            };
            if !is_error_tainted(second_condition)
                && node_text(first_condition, source) == node_text(second_condition, source)
            {
                issues.push(issue(
                    language,
                    "S2760",
                    "This condition repeats the immediately preceding check.",
                    range_of(second_condition),
                ));
            }
        }
    }
    issues
}

/// Initializer entries of an anonymous-object creation as `(name, value)`
/// pairs; shorthand entries yield no pair.
fn anonymous_property_pairs<'t>(creation: Node<'t>) -> Vec<(Node<'t>, Node<'t>)> {
    let mut cursor = creation.walk();
    let named: Vec<Node<'t>> = creation
        .children(&mut cursor)
        .filter(tree_sitter::Node::is_named)
        .collect();
    named
        .chunks(2)
        .filter_map(|pair| match pair {
            [name, value] => Some((*name, *value)),
            _ => None,
        })
        .collect()
}

/// csharpsquid:S3441 — `new { x = x }` spells out a name the compiler
/// already infers.
fn check_redundant_anonymous_properties(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for creation in collect_kinds(root, &["anonymous_object_creation_expression"]) {
        if is_error_tainted(creation) {
            continue;
        }
        for (name, value) in anonymous_property_pairs(creation) {
            if !is_error_tainted(value) && node_text(name, source) == node_text(value, source) {
                issues.push(issue(
                    language,
                    "S3441",
                    "Use the shorthand property form; this assignment repeats the name.",
                    range_of(value),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S3604 — object initializers assigning a member to an equally
/// named variable (`new P { X = x }`).
fn check_redundant_member_initializers(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for initializer in collect_kinds(root, &["initializer_expression"]) {
        if initializer
            .parent()
            .is_none_or(|parent| parent.kind() != "object_creation_expression")
        {
            continue;
        }
        let mut cursor = initializer.walk();
        for entry in initializer
            .children(&mut cursor)
            .filter(|child| child.kind() == "assignment_expression")
        {
            if is_error_tainted(entry) {
                continue;
            }
            let Some((left, right)) = binary_operands(entry) else {
                continue;
            };
            if expression_name(left, source).is_some()
                && expression_name(left, source) == expression_name(right, source)
            {
                issues.push(issue(
                    language,
                    "S3604",
                    "This member initializer assigns the member to itself.",
                    range_of(entry),
                ));
            }
        }
    }
    issues
}

/// Literal node kinds accepted as constant returns.
const LITERAL_KINDS: [&str; 6] = [
    "integer_literal",
    "real_literal",
    "string_literal",
    "character_literal",
    "boolean_literal",
    "null_literal",
];

/// csharpsquid:S3400 — methods whose whole body returns one literal. Entry
/// points and inherited contracts stay untouched.
fn check_constant_returning_methods(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) {
            continue;
        }
        let name = method
            .child_by_field_name("name")
            .map_or("", |name| node_text(name, source));
        let modifiers = modifiers_of(method, source);
        if name == "Main"
            || ["abstract", "virtual", "override", "partial", "extern"]
                .iter()
                .any(|modifier| has_modifier(&modifiers, modifier))
        {
            continue;
        }
        let Some(body) = body_of(method) else {
            continue;
        };
        let statements = block_statements(body);
        let constant_return = match statements.as_slice() {
            [only] if only.kind() == "return_statement" => {
                first_named_child(*only).is_some_and(|value| LITERAL_KINDS.contains(&value.kind()))
            }
            _ => false,
        };
        if constant_return {
            issues.push(issue(
                language,
                "S3400",
                "Remove this method and declare a constant for its value instead.",
                range_of(method),
            ));
        }
    }
    issues
}

/// csharpsquid:S3626 — a jump ending a loop body can never be reached any
/// differently than falling through. Switch sections require their `break`
/// and stay clean.
fn check_redundant_jumps(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for header in collect_kinds(root, &LOOP_KINDS) {
        if is_error_tainted(header) {
            continue;
        }
        for body in embedded_bodies(header) {
            let tail: Vec<Node> = if body.kind() == "block" {
                block_statements(body)
            } else {
                vec![body]
            };
            let Some(last) = tail.last() else {
                continue;
            };
            if matches!(last.kind(), "break_statement" | "continue_statement") {
                issues.push(issue(
                    language,
                    "S3626",
                    "Remove this redundant jump.",
                    range_of(*last),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S1848 — objects created straight into thin air. Exception
/// instantiations belong to S3984 instead.
fn check_dropped_objects(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for creation in bare_creations(root) {
        if !creation_type_text(creation, source).ends_with("Exception") {
            issues.push(issue(
                language,
                "S1848",
                "Either use this created object or remove the instantiation.",
                range_of(creation),
            ));
        }
    }
    issues
}

/// csharpsquid:S3984 — exceptions built but never thrown.
fn check_unthrown_exceptions(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for creation in bare_creations(root) {
        if creation_type_text(creation, source).ends_with("Exception") {
            issues.push(issue(
                language,
                "S3984",
                "Throw this exception or remove the useless instantiation.",
                range_of(creation),
            ));
        }
    }
    issues
}

/// csharpsquid:S3717 — thrown `NotImplementedException`s are tracked so
/// unfinished work stays visible.
fn check_not_implemented_throws(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for throw_statement in collect_kinds(root, &["throw_statement"]) {
        if is_error_tainted(throw_statement) {
            continue;
        }
        let tracked = first_named_child(throw_statement).is_some_and(|thrown| {
            thrown.kind() == "object_creation_expression"
                && simple_name(creation_type_text(thrown, source)) == "NotImplementedException"
        });
        if tracked {
            issues.push(issue(
                language,
                "S3717",
                "Track uses of 'NotImplementedException'.",
                range_of(throw_statement),
            ));
        }
    }
    issues
}

/// Gathers every Tier-A6 constant-fold pattern issue.
fn constant_fold_issues(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_identical_operands(root, source, language));
    issues.extend(check_repeated_chain_conditions(root, source, language));
    issues.extend(check_identical_branches(root, source, language));
    issues.extend(check_duplicate_switch_sections(root, source, language));
    issues.extend(check_duplicate_sibling_methods(root, source, language));
    issues.extend(check_repeated_adjacent_conditions(root, source, language));
    issues.extend(check_redundant_anonymous_properties(root, source, language));
    issues.extend(check_redundant_member_initializers(root, source, language));
    issues.extend(check_constant_returning_methods(root, source, language));
    issues.extend(check_redundant_jumps(root, language));
    issues.extend(check_dropped_objects(root, source, language));
    issues.extend(check_unthrown_exceptions(root, source, language));
    issues.extend(check_not_implemented_throws(root, source, language));
    issues
}

// ---------------------------------------------------------------------------
// A7 — attributes tracked & test contracts
// ---------------------------------------------------------------------------

/// Every attribute application in the file as `(simple name, argument list,
/// attribute node)`, assembly-level ones included.
fn attribute_applications<'t, 's>(
    root: Node<'t>,
    source: &'s str,
) -> Vec<(&'s str, Option<Node<'t>>, Node<'t>)> {
    collect_kinds(root, &["attribute"])
        .into_iter()
        .filter(|node| !is_error_tainted(*node))
        .filter_map(|node| {
            let mut cursor = node.walk();
            let named: Vec<Node> = node
                .children(&mut cursor)
                .filter(tree_sitter::Node::is_named)
                .collect();
            let name = first_named_child(node).map(|name| node_text(name, source))?;
            Some((name, named.get(1).copied(), node))
        })
        .collect()
}

/// csharpsquid:S1133 — uses of `[Obsolete]` are tracked so deprecated code
/// eventually gets removed.
fn check_obsolete_tracked(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (name, _, node) in attribute_applications(root, source) {
        if matches!(name, "Obsolete" | "ObsoleteAttribute") {
            issues.push(issue(
                language,
                "S1133",
                "Deprecated code should be removed.",
                range_of(node),
            ));
        }
    }
    issues
}

/// csharpsquid:S1123 — `[Obsolete]` without an explanation leaves future
/// maintainers guessing.
fn check_obsolete_without_reason(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (name, args, node) in attribute_applications(root, source) {
        if matches!(name, "Obsolete" | "ObsoleteAttribute") && args.is_none() {
            issues.push(issue(
                language,
                "S1123",
                "Document why this code is obsolete with an explanation message.",
                range_of(node),
            ));
        }
    }
    issues
}

/// csharpsquid:S1309 — in-source suppressions are tracked so they stay rare
/// and deliberate.
fn check_suppression_tracked(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (name, _, node) in attribute_applications(root, source) {
        if matches!(name, "SuppressMessage" | "SuppressMessageAttribute") {
            issues.push(issue(
                language,
                "S1309",
                "Track uses of in-source suppressions.",
                range_of(node),
            ));
        }
    }
    for pragma in collect_kinds(root, &["preproc_pragma"]) {
        if !is_error_tainted(pragma) && node_text(pragma, source).contains("warning disable") {
            issues.push(issue(
                language,
                "S1309",
                "Track uses of in-source suppressions.",
                range_of(pragma),
            ));
        }
    }
    issues
}

/// csharpsquid:S1607 — ignored tests silently stop guarding behavior.
fn check_ignored_tests(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (name, _, node) in attribute_applications(root, source) {
        if matches!(name, "Ignore" | "IgnoreAttribute") {
            issues.push(issue(
                language,
                "S1607",
                "Remove this 'Ignore' annotation and fix the test.",
                range_of(node),
            ));
        }
    }
    issues
}

/// csharpsquid:S3431 — `MSTest`'s `ExpectedException` hides which assertion
/// failed; assertions inside the test report precisely.
fn check_expected_exception_attributes(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (name, _, node) in attribute_applications(root, source) {
        if matches!(name, "ExpectedException" | "ExpectedExceptionAttribute") {
            issues.push(issue(
                language,
                "S3431",
                "Replace this 'ExpectedException' annotation with assertions.",
                range_of(node),
            ));
        }
    }
    issues
}

/// csharpsquid:S6513 — coverage exclusions need a justification string.
fn check_coverage_exclusion_reasons(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (name, args, node) in attribute_applications(root, source) {
        let justified = args.is_some_and(|args| {
            collect_kinds(args, &["string_literal"])
                .iter()
                .any(|literal| node_text(*literal, source).len() > 2)
        });
        if matches!(
            name,
            "ExcludeFromCodeCoverage" | "ExcludeFromCodeCoverageAttribute"
        ) && !justified
        {
            issues.push(issue(
                language,
                "S6513",
                "Document the reason for excluding this code from coverage.",
                range_of(node),
            ));
        }
    }
    issues
}

/// csharpsquid:S1210 — `IComparable` implementations owe callers `Equals`
/// and the comparison operators.
fn check_comparable_contracts(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if is_error_tainted(type_node) {
            continue;
        }
        let comparable = base_simple_names(type_node, source)
            .iter()
            .any(|base| base.starts_with("IComparable"));
        if !comparable {
            continue;
        }
        let has_equals = overridden_names(type_node, source).contains("Equals");
        let has_comparison = overloaded_operators(type_node)
            .iter()
            .any(|operator| matches!(*operator, "<" | "<=" | ">" | ">="));
        if !has_equals || !has_comparison {
            issues.push(issue(
                language,
                "S1210",
                "Implement Equals and the comparison operators alongside IComparable.",
                range_of(name_anchor(type_node)),
            ));
        }
    }
    issues
}

/// csharpsquid:S1206 — overriding only one of `Equals`/`GetHashCode` breaks
/// hash-based collections.
fn check_equals_hashcode_pairing(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if is_error_tainted(type_node) {
            continue;
        }
        let overrides = overridden_names(type_node, source);
        for lone in ["Equals", "GetHashCode"] {
            let partner = if lone == "Equals" {
                "GetHashCode"
            } else {
                "Equals"
            };
            if overrides.contains(lone)
                && !overrides.contains(partner)
                && let Some(method) = member_named(type_node, "method_declaration", lone, source)
            {
                issues.push(issue(
                    language,
                    "S1206",
                    format!("Override 'Equals' and 'GetHashCode' together; '{lone}' is alone."),
                    range_of(method),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S2166 — classes named `...Exception` must actually derive
/// from an exception type.
fn check_exception_named_bases(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_declaration in collect_kinds(root, &["class_declaration"]) {
        if is_error_tainted(class_declaration) {
            continue;
        }
        let name = class_declaration
            .child_by_field_name("name")
            .map_or("", |name| node_text(name, source));
        let derives_exception = base_simple_names(class_declaration, source)
            .iter()
            .any(|base| base.ends_with("Exception"));
        if name.ends_with("Exception") && !derives_exception {
            issues.push(issue(
                language,
                "S2166",
                "Derive this exception-named class from an 'Exception' type.",
                range_of(name_anchor(class_declaration)),
            ));
        }
    }
    issues
}

/// csharpsquid:S4027 — exception types provide `( )`, `(string)`, and
/// `(string, Exception)` constructors so callers can wrap uniformly.
fn check_standard_constructors(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const STANDARD_ARITIES: [usize; 3] = [0, 1, 2];
    let mut issues = Vec::new();
    for class_declaration in collect_kinds(root, &["class_declaration"]) {
        if is_error_tainted(class_declaration) {
            continue;
        }
        let derives_exception = base_simple_names(class_declaration, source)
            .iter()
            .any(|base| base.ends_with("Exception"));
        let modifiers = modifiers_of(class_declaration, source);
        if !derives_exception
            || has_modifier(&modifiers, "abstract")
            || has_modifier(&modifiers, "static")
        {
            continue;
        }
        let arities = constructor_arities(class_declaration);
        let complete = STANDARD_ARITIES.iter().all(|arity| arities.contains(arity));
        if !complete {
            issues.push(issue(
                language,
                "S4027",
                "Provide the standard exception constructors.",
                range_of(name_anchor(class_declaration)),
            ));
        }
    }
    issues
}

/// csharpsquid:S3875 — overloading `==` on reference types invites identity
/// confusion; structs are exempt.
fn check_operator_equals_on_classes(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_declaration in collect_kinds(root, &["class_declaration"]) {
        for declaration in member_declarations_of_kind(class_declaration, "operator_declaration") {
            if is_error_tainted(declaration) || overloaded_operator(declaration) != Some("==") {
                continue;
            }
            issues.push(issue(
                language,
                "S3875",
                "Do not overload the equality operator on this reference type.",
                range_of(declaration),
            ));
        }
    }
    let _ = source;
    issues
}

/// The `operator_declaration` overloading `token`, if any.
fn operator_declaration_for<'t>(type_node: Node<'t>, token: &str) -> Option<Node<'t>> {
    member_declarations_of_kind(type_node, "operator_declaration")
        .into_iter()
        .find(|declaration| overloaded_operator(*declaration) == Some(token))
}

/// csharpsquid:S4050 — a `==` overload must come with `!=` and an `Equals`
/// override or equality semantics fall apart.
fn check_equality_operator_pairing(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if is_error_tainted(type_node) {
            continue;
        }
        let operators = overloaded_operators(type_node);
        if operators.contains(&"==")
            && (!operators.contains(&"!=")
                || !overridden_names(type_node, source).contains("Equals"))
            && let Some(declaration) = operator_declaration_for(type_node, "==")
        {
            issues.push(issue(
                language,
                "S4050",
                "Pair this equality operator with '!=' and an 'Equals' override.",
                range_of(declaration),
            ));
        }
    }
    issues
}

/// Named methods that serve as operator alternatives.
const OPERATOR_ALTERNATIVES: [(&str, &str); 4] = [
    ("+", "Add"),
    ("-", "Subtract"),
    ("*", "Multiply"),
    ("/", "Divide"),
];

/// csharpsquid:S4069 — operator overloads deserve named method equivalents.
fn check_operator_named_alternatives(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if is_error_tainted(type_node) {
            continue;
        }
        let names = declared_method_names(type_node, source);
        for token in overloaded_operators(type_node) {
            let alternative = match OPERATOR_ALTERNATIVES
                .iter()
                .find(|(operator, _)| *operator == token)
            {
                Some((_, method)) => Some(*method),
                None => matches!(token, "<" | "<=" | ">" | ">=").then_some("CompareTo"),
            };
            if let Some(alternative) = alternative
                && !names.contains(alternative)
                && let Some(declaration) = operator_declaration_for(type_node, token)
            {
                issues.push(issue(
                    language,
                    "S4069",
                    format!("Provide a named '{alternative}' method alongside this operator."),
                    range_of(declaration),
                ));
            }
        }
    }
    issues
}

/// Methods that must never throw once running.
const SPECIAL_THROW_METHODS: [&str; 5] =
    ["Dispose", "Finalize", "Equals", "GetHashCode", "ToString"];

/// The nearest enclosing method declaration, if any.
fn enclosing_method(node: Node<'_>) -> Option<Node<'_>> {
    ancestors_of(node).find(|ancestor| ancestor.kind() == "method_declaration")
}

/// Whether a type declares a base list at all.
fn has_base_list(type_node: Node<'_>) -> bool {
    let mut cursor = type_node.walk();
    type_node
        .children(&mut cursor)
        .any(|child| child.kind() == "base_list")
}

/// csharpsquid:S3877 — Dispose/Finalize/Equals/GetHashCode/ToString run
/// during sensitive operations and must not throw.
fn check_throws_from_special_methods(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for callable in collect_kinds(root, &["method_declaration", "destructor_declaration"]) {
        if is_error_tainted(callable) {
            continue;
        }
        let special = callable
            .child_by_field_name("name")
            .is_some_and(|name| SPECIAL_THROW_METHODS.contains(&node_text(name, source)));
        if !special {
            continue;
        }
        for throw_statement in collect_kinds(callable, &["throw_statement"]) {
            if is_error_tainted(throw_statement) {
                continue;
            }
            issues.push(issue(
                language,
                "S3877",
                "Do not throw from this method.",
                range_of(throw_statement),
            ));
        }
    }
    let _ = source;
    issues
}

/// csharpsquid:S2225 — `ToString` returning null breaks formatting and
/// string interpolation.
fn check_to_string_null_returns(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method)
            || method
                .child_by_field_name("name")
                .is_none_or(|name| node_text(name, source) != "ToString")
        {
            continue;
        }
        for candidate in collect_kinds(method, &["return_statement", "arrow_expression_clause"]) {
            if first_named_child(candidate).is_some_and(|value| value.kind() == "null_literal") {
                issues.push(issue(
                    language,
                    "S2225",
                    "Do not return null from 'ToString'.",
                    range_of(candidate),
                ));
                break;
            }
        }
    }
    issues
}

/// csharpsquid:S2328 — mutable fields poison hash codes the moment someone
/// mutates them.
fn check_gethashcode_mutable_fields(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if !overridden_names(type_node, source).contains("GetHashCode") {
            continue;
        }
        let mutable_fields = mutable_field_names(type_node, source);
        if mutable_fields.is_empty() {
            continue;
        }
        if let Some(method) = member_named(type_node, "method_declaration", "GetHashCode", source) {
            let poisoned = mutable_fields
                .iter()
                .any(|field| references_identifier(method, field, source));
            if poisoned {
                issues.push(issue(
                    language,
                    "S2328",
                    "Reference only immutable fields from 'GetHashCode'.",
                    range_of(method),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S3397 — calling `base.Equals` from within an `Equals` override
/// recurses into object identity semantics.
fn check_base_equals_misuse(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for invocation in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(invocation) || base_call_name(invocation, source) != Some("Equals") {
            continue;
        }
        let in_equals_override = enclosing_method(invocation).is_some_and(|method| {
            method
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source) == "Equals")
                && has_modifier(&modifiers_of(method, source), "override")
        });
        if in_equals_override {
            issues.push(issue(
                language,
                "S3397",
                "Remove this 'base.Equals' call from the 'Equals' override.",
                range_of(invocation),
            ));
        }
    }
    issues
}

/// csharpsquid:S3249 — types extending `object` directly gain nothing from
/// `base.Equals`/`base.GetHashCode`; those calls equal identity checks.
fn check_base_calls_on_object_types(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for invocation in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(invocation) {
            continue;
        }
        let base_member = base_call_name(invocation, source);
        let relevant = matches!(base_member, Some("Equals" | "GetHashCode"));
        let object_derived =
            enclosing_type(invocation).is_some_and(|type_node| !has_base_list(type_node));
        if relevant && object_derived {
            issues.push(issue(
                language,
                "S3249",
                "Remove this redundant base call; the type extends 'object' directly.",
                range_of(invocation),
            ));
        }
    }
    issues
}

/// csharpsquid:S3897 — declaring a typed `Equals(T)` overload promises
/// `IEquatable<T>`; spell it out on the type.
fn check_typed_equals_needs_iequatable(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method)
            || has_modifier(&modifiers_of(method, source), "override")
            || method
                .child_by_field_name("name")
                .is_none_or(|name| node_text(name, source) != "Equals")
        {
            continue;
        }
        let parameters = parameters_of(method);
        if parameters.len() != 1 {
            continue;
        }
        let parameter_type =
            first_named_child(parameters[0]).map_or("", |type_node| node_text(type_node, source));
        if parameter_type.is_empty() || parameter_type == "object" {
            continue;
        }
        let implements = enclosing_type(method).is_none_or(|type_node| {
            base_simple_names(type_node, source)
                .iter()
                .any(|base| base.starts_with("IEquatable"))
        });
        if !implements {
            issues.push(issue(
                language,
                "S3897",
                "Declare 'IEquatable<T>' on this type.",
                range_of(method),
            ));
        }
    }
    issues
}

/// csharpsquid:S3898 — value types compare by value; `IEquatable<T>` avoids
/// boxing in every comparison.
fn check_structs_implement_iequatable(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for struct_declaration in collect_kinds(root, &["struct_declaration"]) {
        if is_error_tainted(struct_declaration) {
            continue;
        }
        let implements = base_simple_names(struct_declaration, source)
            .iter()
            .any(|base| base.starts_with("IEquatable"));
        if !implements {
            issues.push(issue(
                language,
                "S3898",
                "Implement 'IEquatable<T>' on this value type.",
                range_of(name_anchor(struct_declaration)),
            ));
        }
    }
    issues
}

/// Whether a type declares a finalizer.
fn has_destructor(type_node: Node<'_>) -> bool {
    !member_declarations_of_kind(type_node, "destructor_declaration").is_empty()
}

/// csharpsquid:S3971 — `GC.SuppressFinalize` usage is tracked everywhere.
/// csharpsquid:S3234 additionally flags calls in finalizerless types where it
/// does nothing.
fn check_suppress_finalize_usage(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for access in banned_member_accesses(root, source, "GC", &["SuppressFinalize"]) {
        issues.push(issue(
            language,
            "S3971",
            "Track uses of 'GC.SuppressFinalize'.",
            range_of(access),
        ));
        if enclosing_type(access).is_none_or(|type_node| !has_destructor(type_node)) {
            issues.push(issue(
                language,
                "S3234",
                "Only call 'GC.SuppressFinalize' when a finalizer is defined.",
                range_of(access),
            ));
        }
    }
    issues
}

/// Gathers every Tier-A7 attribute-contract issue.
fn attribute_contract_issues(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_obsolete_tracked(root, source, language));
    issues.extend(check_obsolete_without_reason(root, source, language));
    issues.extend(check_suppression_tracked(root, source, language));
    issues.extend(check_ignored_tests(root, source, language));
    issues.extend(check_expected_exception_attributes(root, source, language));
    issues.extend(check_coverage_exclusion_reasons(root, source, language));
    issues.extend(check_comparable_contracts(root, source, language));
    issues.extend(check_equals_hashcode_pairing(root, source, language));
    issues.extend(check_exception_named_bases(root, source, language));
    issues.extend(check_standard_constructors(root, source, language));
    issues.extend(check_operator_equals_on_classes(root, source, language));
    issues.extend(check_equality_operator_pairing(root, source, language));
    issues.extend(check_operator_named_alternatives(root, source, language));
    issues.extend(check_throws_from_special_methods(root, source, language));
    issues.extend(check_to_string_null_returns(root, source, language));
    issues.extend(check_gethashcode_mutable_fields(root, source, language));
    issues.extend(check_base_equals_misuse(root, source, language));
    issues.extend(check_base_calls_on_object_types(root, source, language));
    issues.extend(check_typed_equals_needs_iequatable(root, source, language));
    issues.extend(check_structs_implement_iequatable(root, source, language));
    issues.extend(check_suppress_finalize_usage(root, source, language));
    issues
}
// ---------------------------------------------------------------------------
// A8 — override/member contracts structural within a type
// ---------------------------------------------------------------------------

/// csharpsquid:S1215 — explicit `GC.Collect` calls fight the garbage
/// collector's own heuristics.
fn check_gc_collect_calls(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    banned_member_accesses(root, source, "GC", &["Collect"])
        .into_iter()
        .map(|access| {
            issue(
                language,
                "S1215",
                "Remove this call to 'GC.Collect'.",
                range_of(access),
            )
        })
        .collect()
}

/// csharpsquid:S1147 — killing the process bypasses cleanup and error
/// handling; return or throw instead.
fn check_exit_method_calls(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for invocation in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(invocation) {
            continue;
        }
        let exits = invocation_targets(
            invocation,
            source,
            Some("Environment"),
            &["Exit", "FailFast"],
        ) || invocation_targets(invocation, source, Some("Application"), &["Exit"]);
        if exits {
            issues.push(issue(
                language,
                "S1147",
                "Remove this call to an exit method.",
                range_of(invocation),
            ));
        }
    }
    issues
}

/// csharpsquid:S106 — console output is not logging; it bypasses levels,
/// sinks, and correlation.
fn check_console_output(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const CONSOLE_OWNERS: [&str; 3] = ["Console", "Console.Out", "Console.Error"];
    collect_kinds(root, &["member_access_expression"])
        .into_iter()
        .filter(|node| !is_error_tainted(*node))
        .filter(|node| {
            expression_name(*node, source)
                .is_some_and(|name| name == "Write" || name == "WriteLine")
                && first_named_child(*node).is_some_and(|receiver| {
                    let text = node_text(receiver, source).trim();
                    CONSOLE_OWNERS.iter().any(|owner| text.ends_with(owner))
                })
        })
        .map(|node| {
            issue(
                language,
                "S106",
                "Replace this console output with proper logging.",
                range_of(node),
            )
        })
        .collect()
}

/// csharpsquid:S2925 — sleeping in tests slows suites and hides races.
fn check_thread_sleep_in_tests(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if !is_test_attributed(method, source) {
            continue;
        }
        for invocation in collect_kinds(method, &["invocation_expression"]) {
            if invocation_targets(invocation, source, Some("Thread"), &["Sleep"]) {
                issues.push(issue(
                    language,
                    "S2925",
                    "Remove this 'Thread.Sleep' from the test.",
                    range_of(invocation),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S3889 — suspended threads hold locks and never resume on
/// their own.
fn check_thread_suspend_resume(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    banned_member_accesses(root, source, "Thread", &["Suspend", "Resume"])
        .into_iter()
        .map(|access| {
            issue(
                language,
                "S3889",
                "Do not suspend or resume threads.",
                range_of(access),
            )
        })
        .collect()
}

/// csharpsquid:S3869 — raw handle leaks defeat `SafeHandle`'s release safety.
fn check_dangerous_get_handle(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    banned_member_accesses(root, source, "SafeHandle", &["DangerousGetHandle"])
        .into_iter()
        .map(|access| {
            issue(
                language,
                "S3869",
                "Remove this 'DangerousGetHandle' call.",
                range_of(access),
            )
        })
        .collect()
}

/// csharpsquid:S3884 — mutating process-wide COM security from managed code
/// corrupts the whole apartment.
fn check_com_security_invocations(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    const BANNED: [&str; 2] = ["CoSetProxyBlanket", "CoInitializeSecurity"];
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| invocation_targets(*invocation, source, None, &BANNED))
        .map(|invocation| {
            issue(
                language,
                "S3884",
                "Do not mutate COM security settings here.",
                range_of(invocation),
            )
        })
        .collect()
}

/// csharpsquid:S3885 — `LoadFrom`/`LoadWithPartialName` resolve assemblies
/// unpredictably; `Assembly.Load` binds by name.
fn check_assembly_load_from(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| {
            invocation_targets(
                *invocation,
                source,
                Some("Assembly"),
                &["LoadFrom", "LoadWithPartialName"],
            )
        })
        .map(|invocation| {
            issue(
                language,
                "S3885",
                "Prefer 'Assembly.Load' over this partial load.",
                range_of(invocation),
            )
        })
        .collect()
}

/// csharpsquid:S3902 — `GetExecutingAssembly` couples code to its physical
/// assembly and breaks when moved.
fn check_get_executing_assembly(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    banned_member_accesses(root, source, "Assembly", &["GetExecutingAssembly"])
        .into_iter()
        .map(|access| {
            issue(
                language,
                "S3902",
                "Remove this 'GetExecutingAssembly' call.",
                range_of(access),
            )
        })
        .collect()
}

/// csharpsquid:S3216 — `ConfigureAwait(true)` is the default and only adds
/// noise; capture the context deliberately with `false`.
fn check_configure_await_usage(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| callee_name(*invocation, source) == Some("ConfigureAwait"))
        .filter(|invocation| {
            invocation_arguments(*invocation).iter().any(|argument| {
                first_named_child(*argument).is_some_and(|value| node_text(value, source) == "true")
            })
        })
        .map(|invocation| {
            issue(
                language,
                "S3216",
                "Pass 'false' to 'ConfigureAwait'.",
                range_of(invocation),
            )
        })
        .collect()
}

/// csharpsquid:S4462 — `.Result`, `.Wait()`, and `GetAwaiter().GetResult()`
/// deadlock thread-pool-synchronized contexts.
fn check_blocking_on_async(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for access in collect_kinds(root, &["member_access_expression"]) {
        if is_error_tainted(access) || expression_name(access, source) != Some("Result") {
            continue;
        }
        let called_like_a_method = access.parent().is_some_and(|parent| {
            parent.kind() == "invocation_expression" && invocation_function(parent) == Some(access)
        });
        if !called_like_a_method {
            issues.push(issue(
                language,
                "S4462",
                "Do not block on async code here.",
                range_of(access),
            ));
        }
    }
    for invocation in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(invocation) {
            continue;
        }
        let zero_arg_wait = callee_name(invocation, source) == Some("Wait")
            && invocation_arguments(invocation).is_empty();
        let get_result_chain = callee_name(invocation, source) == Some("GetResult")
            && invocation_receiver(invocation).and_then(|receiver| callee_name(receiver, source))
                == Some("GetAwaiter");
        if zero_arg_wait || get_result_chain {
            issues.push(issue(
                language,
                "S4462",
                "Do not block on async code here.",
                range_of(invocation),
            ));
        }
    }
    issues
}

/// csharpsquid:S3169 — stacking orderings re-sorts the same sequence.
fn check_repeated_orderings(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| {
            callee_name(*invocation, source).is_some_and(|name| name.starts_with("OrderBy"))
        })
        .filter(|invocation| {
            receiver_chain_matches(*invocation, source, |name| name.starts_with("OrderBy"))
        })
        .map(|invocation| {
            issue(
                language,
                "S3169",
                "Remove this duplicate ordering.",
                range_of(invocation),
            )
        })
        .collect()
}

/// csharpsquid:S2971 — a `Where` feeding a terminal LINQ operator folds into
/// that operator's predicate overload.
fn check_where_terminal_chains(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const TERMINALS: [&str; 8] = [
        "Any",
        "Count",
        "First",
        "FirstOrDefault",
        "Last",
        "LastOrDefault",
        "Single",
        "SingleOrDefault",
    ];
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| TERMINALS.contains(&callee_name(*invocation, source).unwrap_or("")))
        .filter(|invocation| {
            invocation_receiver(*invocation).and_then(|receiver| callee_name(receiver, source))
                == Some("Where")
        })
        .map(|invocation| {
            issue(
                language,
                "S2971",
                "Move this filter into the terminal LINQ call's predicate.",
                range_of(invocation),
            )
        })
        .collect()
}

/// csharpsquid:S6607 — filtering after ordering throws away sorted work;
/// filter first.
fn check_ordering_after_filtering(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| {
            callee_name(*invocation, source).is_some_and(|name| name.starts_with("OrderBy"))
        })
        .filter(|invocation| receiver_chain_matches(*invocation, source, |name| name == "Where"))
        .map(|invocation| {
            issue(
                language,
                "S6607",
                "Apply this ordering after filtering.",
                range_of(invocation),
            )
        })
        .collect()
}

/// csharpsquid:S3267 — a foreach whose whole body conditionally appends one
/// item is a LINQ projection in disguise.
fn check_linqable_loops(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    /// The single `x.Add(y)` statement inside an if body, if present.
    fn lone_add_statement(if_statement: Node<'_>, source: &str) -> bool {
        let bodies = embedded_bodies(if_statement);
        match bodies.as_slice() {
            [body] => {
                let statements = if body.kind() == "block" {
                    block_statements(*body)
                } else {
                    vec![*body]
                };
                match statements.as_slice() {
                    [statement] => {
                        statement.kind() == "expression_statement"
                            && first_named_child(*statement)
                                .and_then(|expression| {
                                    (expression.kind() == "invocation_expression")
                                        .then_some(expression)
                                })
                                .and_then(|invocation| callee_name(invocation, source))
                                == Some("Add")
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }

    let mut issues = Vec::new();
    for foreach_statement in collect_kinds(root, &["foreach_statement"]) {
        if is_error_tainted(foreach_statement) || else_alternative(foreach_statement).is_some() {
            continue;
        }
        let convertible = embedded_bodies(foreach_statement)
            .first()
            .is_some_and(|body| {
                body.kind() == "block" && {
                    let statements = block_statements(*body);
                    match statements.as_slice() {
                        [only] => {
                            only.kind() == "if_statement"
                                && !is_error_tainted(*only)
                                && lone_add_statement(*only, source)
                        }
                        _ => false,
                    }
                }
            });
        if convertible {
            issues.push(issue(
                language,
                "S3267",
                "Rewrite this loop as a LINQ expression.",
                range_of(foreach_statement),
            ));
        }
    }
    issues
}

/// csharpsquid:S4635 — `Substring(0, n)` already starts at the beginning.
fn check_zero_based_substring(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| callee_name(*invocation, source) == Some("Substring"))
        .filter(|invocation| {
            invocation_arguments(*invocation)
                .first()
                .and_then(|argument| first_named_child(*argument))
                .is_some_and(|value| value.kind() == "integer_literal")
                && invocation_arguments(*invocation)
                    .first()
                    .and_then(|argument| first_named_child(*argument))
                    .is_some_and(|value| node_text(value, source) == "0")
        })
        .map(|invocation| {
            issue(
                language,
                "S4635",
                "Use a start index instead of this zero-based 'Substring'.",
                range_of(invocation),
            )
        })
        .collect()
}

/// csharpsquid:S6610 — one-character string arguments have a char-based
/// `StartsWith`/`EndsWith` overload without allocation.
fn check_single_char_overloads(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| {
            matches!(
                callee_name(*invocation, source),
                Some("StartsWith" | "EndsWith")
            )
        })
        .filter(
            |invocation| match invocation_arguments(*invocation).as_slice() {
                [only] => {
                    let literal = first_named_child(*only);
                    literal.is_some_and(|literal| literal.kind() == "string_literal")
                        && literal.is_some_and(|literal| {
                            node_text(literal, source).len() == "\"c\"".len()
                        })
                }
                _ => false,
            },
        )
        .map(|invocation| {
            issue(
                language,
                "S6610",
                "Call the char-based overload with this single character.",
                range_of(invocation),
            )
        })
        .collect()
}

/// csharpsquid:S6617 — `Any(x => x == y)` scans until equality; `Contains`
/// states the intent and optimizes.
fn check_any_with_equality_lambda(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    /// Whether the lambda body compares its parameter against something.
    fn parameter_equality(body: Node<'_>, parameter: &str, source: &str) -> bool {
        body.kind() == "binary_expression"
            && operator_of(body) == Some("==")
            && binary_operands(body).is_some_and(|(left, right)| {
                [left, right]
                    .iter()
                    .any(|operand| expression_name(*operand, source) == Some(parameter))
            })
    }

    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| matches!(callee_name(*invocation, source), Some("Any" | "All")))
        .filter(
            |invocation| match invocation_arguments(*invocation).as_slice() {
                [only] => first_named_child(*only)
                    .and_then(|lambda| (lambda.kind() == "lambda_expression").then_some(lambda))
                    .and_then(|lambda| lambda_shape(lambda, source))
                    .is_some_and(|(parameter, body)| parameter_equality(body, parameter, source)),
                _ => false,
            },
        )
        .map(|invocation| {
            issue(
                language,
                "S6617",
                "Use 'Contains' instead of this equality lambda.",
                range_of(invocation),
            )
        })
        .collect()
}

/// csharpsquid:S6612 — `ConcurrentDictionary` factories must be delegates or
/// every caller pays the evaluation cost.
fn check_concurrent_dictionary_delegates(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    const FACTORY_METHODS: [&str; 2] = ["GetOrAdd", "AddOrUpdate"];
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| {
            FACTORY_METHODS.contains(&callee_name(*invocation, source).unwrap_or(""))
        })
        .filter(|invocation| {
            invocation_arguments(*invocation)
                .iter()
                .skip(1)
                .any(|argument| {
                    first_named_child(*argument)
                        .is_none_or(|value| value.kind() != "lambda_expression")
                })
        })
        .map(|invocation| {
            issue(
                language,
                "S6612",
                "Pass a delegate to this 'ConcurrentDictionary' method.",
                range_of(invocation),
            )
        })
        .collect()
}

/// csharpsquid:S6618 — `FormattableString` flows allocate; `string.Create`
/// formats directly into place.
fn check_formattable_string_flows(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["member_access_expression"])
        .into_iter()
        .filter(|node| !is_error_tainted(*node))
        .filter(|node| {
            first_named_child(*node).is_some_and(|receiver| {
                node_text(receiver, source)
                    .trim()
                    .ends_with("FormattableString")
            })
        })
        .map(|node| {
            issue(
                language,
                "S6618",
                "Prefer 'string.Create' over this 'FormattableString' flow.",
                range_of(node),
            )
        })
        .collect()
}

/// csharpsquid:S3456 — converting a string to a char array only to index or
/// iterate it allocates for nothing; strings are enumerable already.
fn check_string_to_array_iteration(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    /// Whether the node converts through `ToCharArray()`/`ToArray()`.
    fn conversion_call(node: Node<'_>, source: &str) -> bool {
        node.kind() == "invocation_expression"
            && matches!(callee_name(node, source), Some("ToCharArray" | "ToArray"))
    }

    let mut issues = Vec::new();
    for access in collect_kinds(root, &["element_access_expression"]) {
        if is_error_tainted(access) {
            continue;
        }
        if first_named_child(access).is_some_and(|receiver| conversion_call(receiver, source)) {
            issues.push(issue(
                language,
                "S3456",
                "Index the string directly instead of this array conversion.",
                range_of(access),
            ));
        }
    }
    foreach_conversion_issues(root, source, language, &mut issues, conversion_call);
    issues
}

/// The foreach half of csharpsquid:S3456.
fn foreach_conversion_issues(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    issues: &mut Vec<Issue>,
    conversion_call: impl Fn(Node<'_>, &str) -> bool,
) {
    for foreach_statement in collect_kinds(root, &["foreach_statement"]) {
        if is_error_tainted(foreach_statement) {
            continue;
        }
        let mut cursor = foreach_statement.walk();
        let iterates_conversion = foreach_statement
            .children(&mut cursor)
            .any(|child| conversion_call(child, source));
        if iterates_conversion {
            issues.push(issue(
                language,
                "S3456",
                "Iterate the string directly instead of this array conversion.",
                range_of(foreach_statement),
            ));
        }
    }
}

/// csharpsquid:S1643 — `+=` concatenation in a loop is quadratic; use a
/// `StringBuilder`. String evidence comes from a string-literal operand or a
/// `string`-typed left-hand local.
fn check_string_concatenation_in_loops(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["assignment_expression"])
        .into_iter()
        .filter(|assignment| !is_error_tainted(*assignment))
        .filter(|assignment| operator_of(*assignment) == Some("+="))
        .filter(|assignment| has_ancestor_with_kind(*assignment, &LOOP_KINDS))
        .filter(|assignment| {
            let Some((left, right)) = binary_operands(*assignment) else {
                return false;
            };
            !collect_kinds(right, &["string_literal"]).is_empty()
                || left
                    .child_by_field_name("name")
                    .or_else(|| first_named_child(left))
                    .and_then(|identifier| expression_name(identifier, source))
                    .is_some_and(|name| declares_string_local(left, name, source))
        })
        .map(|assignment| {
            issue(
                language,
                "S1643",
                "Use a 'StringBuilder' instead of '+=' concatenation in this loop.",
                range_of(assignment),
            )
        })
        .collect()
}

/// Gathers every Tier-A8 member-contract issue.
fn member_contract_issues(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_gc_collect_calls(root, source, language));
    issues.extend(check_exit_method_calls(root, source, language));
    issues.extend(check_console_output(root, source, language));
    issues.extend(check_thread_sleep_in_tests(root, source, language));
    issues.extend(check_thread_suspend_resume(root, source, language));
    issues.extend(check_dangerous_get_handle(root, source, language));
    issues.extend(check_com_security_invocations(root, source, language));
    issues.extend(check_assembly_load_from(root, source, language));
    issues.extend(check_get_executing_assembly(root, source, language));
    issues.extend(check_configure_await_usage(root, source, language));
    issues.extend(check_blocking_on_async(root, source, language));
    issues.extend(check_repeated_orderings(root, source, language));
    issues.extend(check_where_terminal_chains(root, source, language));
    issues.extend(check_linqable_loops(root, source, language));
    issues.extend(check_zero_based_substring(root, source, language));
    issues.extend(check_single_char_overloads(root, source, language));
    issues.extend(check_any_with_equality_lambda(root, source, language));
    issues.extend(check_concurrent_dictionary_delegates(
        root, source, language,
    ));
    issues.extend(check_formattable_string_flows(root, source, language));
    issues.extend(check_ordering_after_filtering(root, source, language));
    issues.extend(check_string_to_array_iteration(root, source, language));
    issues.extend(check_string_concatenation_in_loops(root, source, language));
    issues
}

// ---------------------------------------------------------------------------
// A9 — literal-content scans
// ---------------------------------------------------------------------------

/// Every plain and verbatim string literal in the file, document order.
/// Interpolated strings carry no static content and are skipped.
fn string_literals(root: Node<'_>) -> Vec<Node<'_>> {
    collect_kinds(root, &["string_literal", "verbatim_string_literal"])
}

fn is_string_literal(node: Node<'_>) -> bool {
    matches!(node.kind(), "string_literal" | "verbatim_string_literal")
}

/// Inner text of a plain or verbatim string literal: quotes and the verbatim
/// `@` prefix stripped; escape sequences stay as written.
fn literal_inner_text<'a>(literal: Node<'_>, source: &'a str) -> &'a str {
    let text = node_text(literal, source);
    let trimmed = text.trim_start_matches('@');
    trimmed
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(trimmed)
}

/// Simple name of an assignment target: bare identifiers and the trailing
/// member of `this.Password`-style accesses.
fn assignment_target_name<'a>(target: Node<'_>, source: &'a str) -> Option<&'a str> {
    match target.kind() {
        "identifier" => Some(node_text(target, source)),
        "member_access_expression" => {
            let name = target.child_by_field_name("name")?;
            Some(node_text(name, source))
        }
        _ => None,
    }
}

/// The initializer of a declarator, if any: its last named child behind the
/// name (`x = "v"`).
fn declarator_initializer<'a>(declarator: Node<'a>, name: Node<'a>) -> Option<Node<'a>> {
    let mut cursor = declarator.walk();
    declarator
        .named_children(&mut cursor)
        .find(|child| child.id() != name.id())
}

/// Every place where a named target receives a string literal: assignments
/// (`password = "x"`) and declarator initializers (`var key = "x";`). Yields
/// `(anchor, target name, literal)` triples in document order.
fn literal_assignments<'t, 's>(
    root: Node<'t>,
    source: &'s str,
) -> Vec<(Node<'t>, &'s str, Node<'t>)> {
    let mut out = Vec::new();
    for assignment in collect_kinds(root, &["assignment_expression"]) {
        let Some(left) = assignment.child_by_field_name("left") else {
            continue;
        };
        let Some(right) = assignment.child_by_field_name("right") else {
            continue;
        };
        if is_string_literal(right)
            && let Some(name) = assignment_target_name(left, source)
        {
            out.push((assignment, name, right));
        }
    }
    for declarator in collect_kinds(root, &["variable_declarator"]) {
        let Some(name) = declarator.child_by_field_name("name") else {
            continue;
        };
        let Some(initializer) = declarator_initializer(declarator, name) else {
            continue;
        };
        if is_string_literal(initializer) {
            out.push((declarator, node_text(name, source), initializer));
        }
    }
    out
}

/// csharpsquid:S1192 — string literals repeated up to the configured
/// threshold deserve a named constant. Occurrences from the second on are
/// flagged; the empty literal is exempt.
fn check_duplicate_string_literals(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut counts: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();
    for literal in string_literals(root) {
        let text = literal_inner_text(literal, source);
        if !text.is_empty() {
            *counts.entry(text).or_insert(0) += 1;
        }
    }
    let threshold = options.duplicate_string_threshold.max(2);
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut issues = Vec::new();
    for literal in string_literals(root) {
        let text = literal_inner_text(literal, source);
        if text.is_empty() || counts[text] < threshold {
            continue;
        }
        if seen.insert(text) {
            continue; // the first occurrence anchors nothing
        }
        issue_text(&mut issues, language, text, counts[text], range_of(literal));
    }
    issues
}

/// One S1192 finding for a repeated literal's non-first occurrence.
fn issue_text(
    issues: &mut Vec<Issue>,
    language: CsLanguage,
    text: &str,
    count: u32,
    range: hoonarqube_ir::Range,
) {
    issues.push(issue(
        language,
        "S1192",
        format!("Define a constant instead of duplicating this literal \"{text}\" {count} times."),
        range,
    ));
}

/// Case-insensitive substring search for a credential word inside a name.
fn credential_word_in<'w>(name: &str, words: &'w [String]) -> Option<&'w str> {
    let lowered = name.to_lowercase();
    words
        .iter()
        .map(String::as_str)
        .find(|word| lowered.contains(&word.to_lowercase()))
}

/// csharpsquid:S2068 — names carrying a credential word must not receive
/// hard-coded string literals.
fn check_hardcoded_credentials(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    literal_assignments(root, source)
        .into_iter()
        .filter(|(_, name, literal)| {
            !literal_inner_text(*literal, source).is_empty()
                && credential_word_in(name, &options.credential_words).is_some()
        })
        .map(|(anchor, name, _)| {
            issue(
                language,
                "S2068",
                format!("Review this hard-coded credential assigned through '{name}'."),
                range_of(anchor),
            )
        })
        .collect()
}

/// Matches the catalog default `secretWords` shapes natively
/// (`api[_\-]?key`) and degrades every other entry to a case-insensitive
/// substring search.
fn secret_word_in<'w>(name: &str, words: &'w [String]) -> Option<&'w str> {
    let lowered = name.to_lowercase();
    words.iter().map(String::as_str).find(|word| {
        if word.eq_ignore_ascii_case(r"api[_\-]?key") {
            lowered.contains("apikey") || lowered.contains("api_key") || lowered.contains("api-key")
        } else {
            lowered.contains(&word.to_lowercase())
        }
    })
}

/// Entropy heuristic: enough distinct character classes and a non-trivial
/// length separate real secrets from placeholder values like `"token"`.
fn looks_like_secret(value: &str, sensibility: u32) -> bool {
    let classes = [
        value.chars().any(|c| c.is_ascii_lowercase()),
        value.chars().any(|c| c.is_ascii_uppercase()),
        value.chars().any(|c| c.is_ascii_digit()),
        value.chars().any(|c| !c.is_ascii_alphanumeric()),
    ];
    value.len() >= 8
        && classes.iter().filter(|seen| **seen).count()
            >= usize::try_from(sensibility).unwrap_or(usize::MAX)
}

/// csharpsquid:S6418 — names matching a secret word plus high-entropy
/// literal values point at hard-coded secrets.
fn check_hardcoded_secrets(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    literal_assignments(root, source)
        .into_iter()
        .filter(|(_, name, literal)| {
            secret_word_in(name, &options.secret_words).is_some()
                && looks_like_secret(
                    literal_inner_text(*literal, source),
                    options.secret_randomness_sensibility,
                )
        })
        .map(|(anchor, _, _)| {
            issue(
                language,
                "S6418",
                "Review this potentially hard-coded secret.",
                range_of(anchor),
            )
        })
        .collect()
}

/// Strict dotted-quad IPv4 shape with octets in range; versions and dates
/// never fully match.
fn is_ipv4_address(text: &str) -> bool {
    let octets: Vec<&str> = text.split('.').collect();
    octets.len() == 4
        && octets.iter().all(|octet| {
            !octet.is_empty()
                && octet.len() <= 3
                && octet.bytes().all(|byte| byte.is_ascii_digit())
                && octet.parse::<u16>().is_ok_and(|value| value <= 255)
        })
}

/// csharpsquid:S1313 — hard-coded IP addresses belong in configuration.
fn check_hardcoded_ip_addresses(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    string_literals(root)
        .into_iter()
        .filter(|literal| is_ipv4_address(literal_inner_text(*literal, source)))
        .map(|literal| {
            issue(
                language,
                "S1313",
                "Refactor this code to not use hard-coded IP addresses.",
                range_of(literal),
            )
        })
        .collect()
}

/// URI schemes whose hard-coded presence S1075 tracks.
const URI_SCHEMES: [&str; 7] = [
    "http://", "https://", "ftp://", "ftps://", "file://", "ws://", "wss://",
];

/// csharpsquid:S1075 — URIs belong in configuration, not literals.
fn check_hardcoded_uris(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    string_literals(root)
        .into_iter()
        .filter(|literal| {
            let lowered = literal_inner_text(*literal, source).to_lowercase();
            URI_SCHEMES.iter().any(|scheme| lowered.starts_with(scheme))
        })
        .map(|literal| {
            issue(
                language,
                "S1075",
                "Refactor your code not to use hard-coded URLs.",
                range_of(literal),
            )
        })
        .collect()
}

/// SQL keywords whose squeezed spelling (`SELECT*FROM`) betrays concatenated
/// query strings.
const SQL_KEYWORDS: [&str; 12] = [
    "select", "insert", "update", "delete", "drop", "alter", "create", "truncate", "union",
    "merge", "exec", "execute",
];

/// SQL keywords inside the literal that touch a following punctuation symbol
/// instead of whitespace (`SELECT*`). Longer words merely containing a
/// keyword (`SELECTION`) stay clean.
fn squeezed_sql_keywords(text: &str) -> Vec<&'static str> {
    let lowered = text.to_lowercase();
    SQL_KEYWORDS
        .iter()
        .filter(|keyword| {
            let mut search_from = 0;
            while let Some(found) = lowered[search_from..].find(*keyword) {
                let start = search_from + found;
                let end = start + keyword.len();
                let bytes = lowered.as_bytes();
                let word_started = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
                let squeezed = end < bytes.len()
                    && !bytes[end].is_ascii_whitespace()
                    && !bytes[end].is_ascii_alphanumeric();
                if word_started && squeezed {
                    return true;
                }
                search_from = start + keyword.len();
            }
            false
        })
        .copied()
        .collect()
}

/// csharpsquid:S2857 — SQL keywords must be delimited by whitespace;
/// glued spellings indicate dynamically concatenated queries.
fn check_sql_keyword_delimiters(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    string_literals(root)
        .into_iter()
        .flat_map(|literal| {
            squeezed_sql_keywords(literal_inner_text(literal, source))
                .into_iter()
                .map(move |keyword| {
                    issue(
                        language,
                        "S2857",
                        format!(
                            "Delimit the SQL keyword '{}' with whitespace.",
                            keyword.to_ascii_uppercase()
                        ),
                        range_of(literal),
                    )
                })
        })
        .collect()
}

/// Hand-rolled syntactic validation of regular-expression patterns:
/// balanced groups and classes, well-placed quantifiers, valid escapes, and
/// sane character-class ranges — no regex engine required.
fn is_valid_regex(pattern: &str) -> bool {
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    let mut depth: usize = 0;
    let mut atom = false;
    while i < chars.len() {
        match chars[i] {
            '\\' => {
                if i + 1 >= chars.len() {
                    return false;
                }
                i += 2;
                atom = true;
            }
            '[' => {
                if !scan_regex_class(&chars, i, &mut i) {
                    return false;
                }
                atom = true;
            }
            '(' => {
                depth += 1;
                if chars.get(i + 1) == Some(&'?') {
                    // Group header such as `(?:`, `(?=`, `(?<=`, `(?<name>`:
                    // consume through its terminator so inner quantifier
                    // positions stay correct.
                    let mut j = i + 2;
                    while j < chars.len() && !matches!(chars[j], ':' | '=' | '!' | '>' | ')') {
                        j += 1;
                    }
                    match chars.get(j) {
                        Some(')') => {
                            depth -= 1;
                            i = j + 1;
                        }
                        Some(_) => i = j + 1,
                        None => return false,
                    }
                } else {
                    i += 1;
                }
                atom = false;
            }
            ')' => {
                if depth == 0 {
                    return false;
                }
                depth -= 1;
                i += 1;
                atom = true;
            }
            '|' => {
                i += 1;
                atom = false;
            }
            '*' | '+' | '?' => {
                if !atom {
                    return false;
                }
                while i < chars.len() && matches!(chars[i], '*' | '+' | '?') {
                    i += 1;
                }
            }
            '{' => {
                let mut j = i + 1;
                while j < chars.len() && chars[j].is_ascii_digit() {
                    j += 1;
                }
                if j < chars.len() && chars[j] == ',' {
                    j += 1;
                    while j < chars.len() && chars[j].is_ascii_digit() {
                        j += 1;
                    }
                }
                if atom && j < chars.len() && chars[j] == '}' && j > i + 1 {
                    i = j + 1;
                } else {
                    i += 1;
                }
                atom = true;
            }
            _ => {
                i += 1;
                atom = true;
            }
        }
    }
    depth == 0
}

/// Scans one `[...]` character class starting at `start`, advancing `i`
/// past it. Rejects unterminated classes and reversed ranges (`[z-a]`);
/// false means the pattern is invalid.
fn scan_regex_class(chars: &[char], start: usize, i: &mut usize) -> bool {
    let mut j = start + 1;
    if chars.get(j) == Some(&'^') {
        j += 1;
    }
    if chars.get(j) == Some(&']') {
        j += 1;
    }
    let mut prev: Option<char> = None;
    while j < chars.len() {
        match chars[j] {
            ']' => {
                *i = j + 1;
                return true;
            }
            '\\' => {
                if j + 1 >= chars.len() {
                    *i = chars.len();
                    return false;
                }
                j += 2;
                prev = None;
            }
            '-' if prev.is_some() && chars.get(j + 1).is_some_and(|hi| *hi != ']') => {
                let hi = chars[j + 1];
                if hi != '\\' && prev.is_some_and(|lo| lo > hi) {
                    *i = chars.len();
                    return false;
                }
                prev = None;
                j += 1;
            }
            _ => {
                prev = Some(chars[j]);
                j += 1;
            }
        }
    }
    *i = chars.len();
    false
}

fn argument_nodes(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() == "argument")
        .collect()
}

/// The expression inside an `argument` wrapper node.
fn argument_expression(argument: Node<'_>) -> Node<'_> {
    let mut cursor = argument.walk();
    argument
        .named_children(&mut cursor)
        .next()
        .unwrap_or(argument)
}

/// Whether an object creation instantiates `Regex` directly.
fn is_regex_creation(creation: Node<'_>, source: &str) -> bool {
    creation
        .child_by_field_name("type")
        .is_none_or(|type_node| node_text(type_node, source) != "Regex")
        .then_some(())
        .is_none()
}

/// Methods of `System.Text.RegularExpressions.Regex` taking a pattern.
const REGEX_PATTERN_METHODS: [&str; 5] = ["IsMatch", "Match", "Matches", "Replace", "Split"];

/// The pattern argument of a static `Regex.Method(...)` call, if any.
fn regex_static_pattern<'t>(invocation: Node<'t>, source: &str) -> Option<Node<'t>> {
    let function = invocation.child_by_field_name("function")?;
    if function.kind() != "member_access_expression" {
        return None;
    }
    let receiver = function.child_by_field_name("expression")?;
    let name = function.child_by_field_name("name")?;
    if node_text(receiver, source) != "Regex"
        || !REGEX_PATTERN_METHODS.contains(&node_text(name, source))
    {
        return None;
    }
    let arguments = invocation.child_by_field_name("arguments")?;
    argument_nodes(arguments)
        .get(1)
        .copied()
        .map(argument_expression)
}

/// Pattern arguments worth validating: first argument of a `new Regex(...)`
/// creation and second argument of a static `Regex.Method(...)` call.
fn regex_pattern_arguments<'t>(root: Node<'t>, source: &str) -> Vec<(Node<'t>, Node<'t>)> {
    let mut out = Vec::new();
    for creation in collect_kinds(root, &["object_creation_expression"]) {
        if !is_regex_creation(creation, source) {
            continue;
        }
        let Some(arguments) = creation.child_by_field_name("arguments") else {
            continue;
        };
        if let Some(pattern) = argument_nodes(arguments).first() {
            out.push((creation, argument_expression(*pattern)));
        }
    }
    for invocation in collect_kinds(root, &["invocation_expression"]) {
        if let Some(pattern) = regex_static_pattern(invocation, source) {
            out.push((invocation, pattern));
        }
    }
    out
}

/// Whether any argument mentions `TimeSpan`, the timeout carrier.
fn arguments_carry_timeout(arguments: Node<'_>, source: &str) -> bool {
    argument_nodes(arguments)
        .iter()
        .any(|argument| node_text(*argument, source).contains("TimeSpan"))
}

/// csharpsquid:S5856 — regular expressions must be syntactically valid.
fn check_regex_syntax(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    regex_pattern_arguments(root, source)
        .into_iter()
        .filter(|(_, pattern)| {
            is_string_literal(*pattern) && !is_valid_regex(literal_inner_text(*pattern, source))
        })
        .map(|(anchor, _)| {
            issue(
                language,
                "S5856",
                "Fix this invalid regular expression.",
                range_of(anchor),
            )
        })
        .collect()
}

/// csharpsquid:S6444 — every Regex construction and static pattern call
/// carries a timeout.
fn check_regex_timeouts(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for creation in collect_kinds(root, &["object_creation_expression"]) {
        if !is_regex_creation(creation, source) {
            continue;
        }
        let Some(arguments) = creation.child_by_field_name("arguments") else {
            continue;
        };
        if !arguments_carry_timeout(arguments, source) {
            issues.push(issue(
                language,
                "S6444",
                "Provide a timeout when constructing this 'Regex'.",
                range_of(creation),
            ));
        }
    }
    for invocation in collect_kinds(root, &["invocation_expression"]) {
        if regex_static_pattern(invocation, source).is_none() {
            continue;
        }
        let timed_out = invocation
            .child_by_field_name("arguments")
            .is_some_and(|arguments| arguments_carry_timeout(arguments, source));
        if !timed_out {
            issues.push(issue(
                language,
                "S6444",
                "Provide a timeout for this 'Regex' call.",
                range_of(invocation),
            ));
        }
    }
    issues
}

/// csharpsquid:S2479 — raw whitespace/control characters inside literals
/// hide their intent; spell them as escape sequences.
fn check_raw_control_characters(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    string_literals(root)
        .into_iter()
        .filter(|literal| {
            literal_inner_text(*literal, source)
                .chars()
                .any(char::is_control)
        })
        .map(|literal| {
            issue(
                language,
                "S2479",
                "Replace this control character with its escape sequence form.",
                range_of(literal),
            )
        })
        .collect()
}

/// Longest trailing run of suffix letters whose remainder still ends in a
/// digit yields the literal's suffix; lowercase suffixes are flagged. Hex
/// digits outside the suffix set fall out naturally (`0xd` stays clean).
fn has_lowercase_suffix(text: &str) -> bool {
    const SUFFIX_LETTERS: [char; 10] = ['u', 'U', 'l', 'L', 'f', 'F', 'd', 'D', 'm', 'M'];
    let run_len = text
        .chars()
        .rev()
        .take_while(|letter| SUFFIX_LETTERS.contains(letter))
        .count();
    for k in 0..=run_len.min(text.len() - 1) {
        if text.as_bytes()[text.len() - k - 1].is_ascii_digit() {
            return text[text.len() - k..]
                .chars()
                .any(|letter: char| letter.is_ascii_lowercase());
        }
    }
    false
}

/// csharpsquid:S818 — numeric literal suffixes are uppercase.
fn check_numeric_suffix_case(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["integer_literal", "real_literal"])
        .into_iter()
        .filter(|literal| has_lowercase_suffix(node_text(*literal, source)))
        .map(|literal| {
            issue(
                language,
                "S818",
                "Uppercase this numeric literal suffix.",
                range_of(literal),
            )
        })
        .collect()
}

/// Gathers every Tier-A9 literal-content issue.
fn literal_content_issues(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_duplicate_string_literals(
        root, source, language, options,
    ));
    issues.extend(check_hardcoded_credentials(root, source, language, options));
    issues.extend(check_hardcoded_secrets(root, source, language, options));
    issues.extend(check_hardcoded_ip_addresses(root, source, language));
    issues.extend(check_hardcoded_uris(root, source, language));
    issues.extend(check_sql_keyword_delimiters(root, source, language));
    issues.extend(check_regex_syntax(root, source, language));
    issues.extend(check_regex_timeouts(root, source, language));
    issues.extend(check_raw_control_characters(root, source, language));
    issues.extend(check_numeric_suffix_case(root, source, language));
    issues
}

// ---------------------------------------------------------------------------
// A10 — in-file usage heuristics
// ---------------------------------------------------------------------------

/// Number of whole-word occurrences of `word` in `text`. Identifier
/// characters are alphanumeric plus `_`, so `field` never matches `my_field`.
fn count_word_occurrences(text: &str, word: &str) -> usize {
    let bytes = text.as_bytes();
    let mut count = 0;
    let mut from = 0;
    while let Some(found) = text[from..].find(word) {
        let start = from + found;
        let end = start + word.len();
        let left_clean =
            start == 0 || !(bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_');
        let right_clean =
            end >= bytes.len() || !(bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_');
        if left_clean && right_clean {
            count += 1;
        }
        from = start + word.len();
    }
    count
}

/// Last meaningful name segment of a using directive's target
/// (`using Alias = System.IO.File;` → `File`).
fn using_target_segment<'a>(directive: Node<'_>, source: &'a str) -> Option<&'a str> {
    let text = node_text(directive, source).trim();
    let inner = text.strip_prefix("using")?.trim();
    let inner = inner.strip_prefix("global").map_or(inner, str::trim);
    let inner = inner.strip_prefix("static").map_or(inner, str::trim);
    let inner = inner.strip_suffix(';')?.trim();
    let target = match inner.split_once('=') {
        Some((_, aliased)) => aliased.trim(),
        None => inner,
    };
    if target.is_empty() {
        None
    } else {
        target.rsplit('.').next()
    }
}

/// csharpsquid:S1128 — using directives whose target segment appears nowhere
/// else in the file import nothing this file uses.
fn check_unused_usings(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let directives = collect_kinds(root, &["using_directive"]);
    if directives.is_empty() {
        return Vec::new();
    }
    // Blank every directive (back to front keeps earlier offsets valid)
    // before counting references in the remainder.
    let mut body = source.to_string();
    for directive in directives.iter().rev() {
        let range = directive.byte_range();
        let length = range.end - range.start;
        body.replace_range(range, &" ".repeat(length));
    }
    directives
        .into_iter()
        .filter_map(|directive| {
            let segment = using_target_segment(directive, source)?;
            (count_word_occurrences(&body, segment) == 0).then_some(directive)
        })
        .map(|directive| {
            issue(
                language,
                "S1128",
                "Remove this unnecessary 'using'.",
                range_of(directive),
            )
        })
        .collect()
}

/// One private member candidate for the S1144 audit.
struct PrivateMember<'t> {
    anchor: Node<'t>,
    name: String,
    kind_word: &'static str,
}

/// Collects private methods, properties, fields, and events declared by
/// non-partial types. Constants are exempt (they often document intent),
/// attributed members may be reflection hooks, and `Main` is an entry point.
fn private_member_candidates<'t>(root: Node<'t>, source: &str) -> Vec<PrivateMember<'t>> {
    let mut candidates = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if has_modifier(&modifiers_of(type_node, source), "partial") {
            continue;
        }
        for member in type_members(type_node) {
            match member.kind() {
                "method_declaration" | "property_declaration" => {
                    let Some(name_node) = member.child_by_field_name("name") else {
                        continue;
                    };
                    if accessibility_rank(&modifiers_of(member, source)) != 1
                        || !attributes_of(member, source).is_empty()
                        || node_text(name_node, source) == "Main"
                    {
                        continue;
                    }
                    candidates.push(PrivateMember {
                        anchor: name_node,
                        name: node_text(name_node, source).to_string(),
                        kind_word: if member.kind() == "method_declaration" {
                            "method"
                        } else {
                            "property"
                        },
                    });
                }
                "field_declaration" => {
                    if accessibility_rank(&modifiers_of(member, source)) == 1
                        && !has_modifier(&modifiers_of(member, source), "const")
                        && attributes_of(member, source).is_empty()
                    {
                        candidates.extend(private_declarators(member, source, "field"));
                    }
                }
                "event_field_declaration"
                    if accessibility_rank(&modifiers_of(member, source)) == 1
                        && attributes_of(member, source).is_empty() =>
                {
                    candidates.extend(private_declarators(member, source, "event"));
                }
                _ => {}
            }
        }
    }
    candidates
}

/// Declarator candidates of a field-like declaration.
fn private_declarators<'t>(
    declaration: Node<'t>,
    source: &str,
    kind_word: &'static str,
) -> Vec<PrivateMember<'t>> {
    collect_kinds(declaration, &["variable_declarator"])
        .into_iter()
        .filter_map(|declarator| {
            let name_node = declarator.child_by_field_name("name")?;
            Some(PrivateMember {
                anchor: name_node,
                name: node_text(name_node, source).to_string(),
                kind_word,
            })
        })
        .collect()
}

/// csharpsquid:S1144 — unused private types and members are dead weight.
/// Overloads sharing one name must all be unreferenced before the name dies;
/// partial types span files and stay untouched.
fn check_unused_private_members(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    let members = private_member_candidates(root, source);
    let mut declared: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for member in &members {
        *declared.entry(&member.name).or_insert(0) += 1;
    }
    for member in &members {
        if count_word_occurrences(source, &member.name) <= declared[member.name.as_str()] {
            issues.push(issue(
                language,
                "S1144",
                format!("Remove this unused private {}.", member.kind_word),
                range_of(member.anchor),
            ));
        }
    }
    // Nested types default to private; partial ones span files.
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        let mods = modifiers_of(type_node, source);
        if has_modifier(&mods, "partial") || type_declared_rank(type_node, source) != 1 {
            continue;
        }
        let Some(name_node) = type_node.child_by_field_name("name") else {
            continue;
        };
        let name = node_text(name_node, source);
        if count_word_occurrences(source, name) <= 1 {
            issues.push(issue(
                language,
                "S1144",
                format!("Remove this unused private {name}."),
                range_of(name_node),
            ));
        }
    }
    issues
}

/// csharpsquid:S1481 — local variables nobody reads are noise. Discard
/// declarations (`_`) are exempt by convention.
fn check_unused_locals(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["local_declaration_statement"])
        .into_iter()
        .filter(|statement| !has_modifier(&modifiers_of(*statement, source), "const"))
        .flat_map(|statement| collect_kinds(statement, &["variable_declarator"]))
        .filter_map(|declarator| {
            let name = declarator.child_by_field_name("name")?;
            let text = node_text(name, source);
            (text != "_").then_some((declarator, text))
        })
        .filter(|(_, text)| count_word_occurrences(source, text) <= 1)
        .map(|(declarator, _)| {
            issue(
                language,
                "S1481",
                "Remove this unused local variable.",
                range_of(declarator),
            )
        })
        .collect()
}

/// Whether `root`'s subtree mentions the identifier `name`, ignoring
/// parameter lists (where the parameter itself is declared).
fn mentions_identifier_outside_parameter_list(root: Node<'_>, name: &str, source: &str) -> bool {
    if root.kind() == "parameter_list" {
        return false;
    }
    if root.kind() == "identifier" {
        return node_text(root, source) == name;
    }
    let mut cursor = root.walk();
    root.children(&mut cursor)
        .any(|child| mentions_identifier_outside_parameter_list(child, name, source))
}

/// Modifiers whose callables keep their signatures regardless of usage.
const SIGNATURE_KEEPING_MODIFIERS: [&str; 8] = [
    "public",
    "protected",
    "internal",
    "virtual",
    "override",
    "abstract",
    "partial",
    "extern",
];

/// csharpsquid:S1172 — parameters no body ever reads mislead callers.
/// Visible, virtual, abstract, partial, and extern callables keep their
/// signatures; discard names (`_`) are exempt by convention.
fn check_unused_method_parameters(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["method_declaration", "constructor_declaration"])
        .into_iter()
        .filter(|callable| {
            !modifiers_of(*callable, source)
                .iter()
                .any(|modifier| SIGNATURE_KEEPING_MODIFIERS.contains(modifier))
        })
        .flat_map(|callable| {
            parameters_of(callable)
                .into_iter()
                .map(move |parameter| (callable, parameter))
        })
        .filter_map(|(callable, parameter)| {
            let name = parameter.child_by_field_name("name")?;
            let text = node_text(name, source);
            (text != "_").then_some((callable, parameter, text))
        })
        .filter(|(callable, _, name)| {
            !mentions_identifier_outside_parameter_list(*callable, name, source)
        })
        .map(|(_, parameter, name)| {
            issue(
                language,
                "S1172",
                format!("Remove this unused method parameter '{name}'."),
                range_of(parameter),
            )
        })
        .collect()
}

/// Whether a numeric literal's value is exactly -1, 0, or 1.
fn is_small_allowed_number(text: &str) -> bool {
    if let Some(value) = integer_literal_value(text) {
        return value <= 1;
    }
    // Real literals: spell out zero and one textually to stay exact.
    let base = text.trim_end_matches(|c: char| c.is_ascii_alphabetic());
    let Some((integer, fraction)) = base.split_once('.') else {
        return false;
    };
    let normalized = integer.trim_start_matches('0');
    let fraction_all_zero = fraction.bytes().all(|digit| digit == b'0');
    (normalized.is_empty() && fraction_all_zero)
        || (normalized == "1" && (fraction.is_empty() || fraction_all_zero))
}

/// Contexts where even large numbers are not magic: enumeration members,
/// constant declarations, and parameter defaults.
fn magic_number_exempt(mut literal: Node<'_>, source: &str) -> bool {
    while let Some(parent) = literal.parent() {
        match parent.kind() {
            "enum_member_declaration" | "parameter" => return true,
            "field_declaration" | "local_declaration_statement" => {
                return has_modifier(&modifiers_of(parent, source), "const");
            }
            _ => {}
        }
        literal = parent;
    }
    false
}

/// csharpsquid:S109 — numbers beyond -1/0/1 deserve names.
fn check_magic_numbers(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["integer_literal", "real_literal"])
        .into_iter()
        .filter(|literal| {
            !magic_number_exempt(*literal, source)
                && !is_small_allowed_number(node_text(*literal, source))
        })
        .map(|literal| {
            issue(
                language,
                "S109",
                "Replace this magic number with a named constant.",
                range_of(literal),
            )
        })
        .collect()
}

/// csharpsquid:S3264 — events nobody raises can never inform anybody.
/// Subscriptions alone do not raise; this in-file heuristic only certifies
/// events whose name appears nowhere beyond its declaration.
fn check_uninvoked_events(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let declared: Vec<(Node<'_>, &str)> = collect_kinds(root, &["event_field_declaration"])
        .into_iter()
        .flat_map(|declaration| collect_kinds(declaration, &["variable_declarator"]))
        .filter_map(|declarator| {
            let name = declarator.child_by_field_name("name")?;
            Some((declarator, node_text(name, source)))
        })
        .collect();
    if declared.is_empty() {
        return Vec::new();
    }
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for (_, name) in &declared {
        *counts.entry(name).or_insert(0) += 1;
    }
    declared
        .into_iter()
        .filter(|(_, name)| count_word_occurrences(source, name) <= counts[name])
        .map(|(declarator, name)| {
            issue(
                language,
                "S3264",
                format!("Invoke the event '{name}' or remove it."),
                range_of(declarator),
            )
        })
        .collect()
}

/// Gathers every Tier-A10 in-file usage heuristic issue.
fn usage_heuristic_issues(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_unused_usings(root, source, language));
    issues.extend(check_unused_private_members(root, source, language));
    issues.extend(check_unused_locals(root, source, language));
    issues.extend(check_unused_method_parameters(root, source, language));
    issues.extend(check_magic_numbers(root, source, language));
    issues.extend(check_uninvoked_events(root, source, language));
    issues
}

// ---------------------------------------------------------------------------
// A11 — field/static/threading declaration contracts
// ---------------------------------------------------------------------------

/// Whether a callable declares an implementation body (not just `;`).
fn has_body_block(callable: Node<'_>) -> bool {
    callable.child_by_field_name("body").is_some()
}

/// csharpsquid:S3251 — a `partial` method without any implementing part in
/// this file never runs. Partial types span files, so implementations living
/// elsewhere are out of reach for this analyzer.
fn check_partial_methods_implemented(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let partials: Vec<(Node<'_>, &str, bool)> = collect_kinds(root, &["method_declaration"])
        .into_iter()
        .filter(|method| has_modifier(&modifiers_of(*method, source), "partial"))
        .filter_map(|method| {
            let name = node_text(method.child_by_field_name("name")?, source);
            Some((method, name, has_body_block(method)))
        })
        .collect();
    let mut implemented: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for (_, name, has_body) in &partials {
        if *has_body {
            implemented.insert(name);
        }
    }
    partials
        .into_iter()
        .filter_map(move |(method, name, _)| {
            (!implemented.contains(name)).then_some((method, name))
        })
        .map(|(method, name)| {
            issue(
                language,
                "S3251",
                format!("Implement or remove this partial method '{name}'."),
                range_of(method),
            )
        })
        .collect()
}

/// csharpsquid:S3052 — fields initialized to their type's default value gain
/// nothing from the explicit assignment.
fn is_default_value_expression(node: Node<'_>, source: &str) -> bool {
    match node.kind() {
        "null_literal" | "default_expression" => true,
        "boolean_literal" => node_text(node, source) == "false",
        "character_literal" => node_text(node, source) == "'\\0'",
        "integer_literal" => integer_literal_value(node_text(node, source)) == Some(0),
        "real_literal" => {
            let base = node_text(node, source).trim_end_matches(|c: char| c.is_ascii_alphabetic());
            base.bytes().all(|byte| byte == b'0' || byte == b'.')
                && base.bytes().any(|byte| byte == b'0')
        }
        _ => false,
    }
}

/// csharpsquid:S3052 — drop field initializers spelling the default value.
fn check_default_field_initializers(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["field_declaration"])
        .into_iter()
        .flat_map(|field| collect_kinds(field, &["variable_declarator"]))
        .filter_map(|declarator| {
            Some((
                declarator,
                declarator_initializer(declarator, declarator.child_by_field_name("name")?),
            ))
        })
        .filter(|(_, initializer)| {
            initializer.is_some_and(|node| is_default_value_expression(node, source))
        })
        .map(|(declarator, _)| {
            issue(
                language,
                "S3052",
                "Remove this redundant initialization to the default value.",
                range_of(declarator),
            )
        })
        .collect()
}

/// Static, non-constant field declarators declared directly by a type.
fn static_field_declarators<'t>(type_node: Node<'t>, source: &'t str) -> Vec<Node<'t>> {
    member_declarations_of_kind(type_node, "field_declaration")
        .into_iter()
        .filter(|field| {
            let mods = modifiers_of(*field, source);
            has_modifier(&mods, "static") && !has_modifier(&mods, "const")
        })
        .flat_map(|field| collect_kinds(field, &["variable_declarator"]))
        .collect()
}

/// Names assigned on the left of assignments inside `scope`.
fn assigned_names<'a>(scope: Node<'_>, source: &'a str) -> Vec<&'a str> {
    collect_kinds(scope, &["assignment_expression"])
        .into_iter()
        .filter_map(|assignment| {
            assignment
                .child_by_field_name("left")
                .filter(|left| left.kind() == "identifier")
                .map(|left| node_text(left, source))
        })
        .collect()
}

/// csharpsquid:S3963 — static fields assigned only inside the static
/// constructor belong inline with their declarations.
fn check_static_fields_initialized_inline(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        let static_ctor = member_declarations_of_kind(type_node, "constructor_declaration")
            .into_iter()
            .filter(|ctor| has_modifier(&modifiers_of(*ctor, source), "static"))
            .find_map(|ctor| ctor.child_by_field_name("body").map(|body| (ctor, body)));
        let Some((_, body)) = static_ctor else {
            continue;
        };
        let assigned: std::collections::HashSet<&str> =
            assigned_names(body, source).into_iter().collect();
        if assigned.is_empty() {
            continue;
        }
        for declarator in static_field_declarators(type_node, source) {
            let Some(name_node) = declarator.child_by_field_name("name") else {
                continue;
            };
            let name = node_text(name_node, source);
            if assigned.contains(name) && declarator_initializer(declarator, name_node).is_none() {
                issues.push(issue(
                    language,
                    "S3963",
                    format!("Initialize '{name}' inline instead of in the static constructor."),
                    range_of(name_node),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S3253 — constructors that only restate what the compiler
/// generates, and finalizers that merely chain disposal, are noise.
fn check_redundant_constructors(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for ctor in collect_kinds(root, &["constructor_declaration"]) {
        let mods = modifiers_of(ctor, source);
        // Private parameterless constructors can deliberately block
        // instantiation; visible ones add nothing.
        if accessibility_rank(&mods) < 2 || !parameters_of(ctor).is_empty() {
            continue;
        }
        let Some(body) = ctor.child_by_field_name("body") else {
            continue;
        };
        if body.named_child_count() == 0 {
            issues.push(issue(
                language,
                "S3253",
                "Remove this redundant constructor.",
                range_of(ctor),
            ));
        }
    }
    for dtor in collect_kinds(root, &["destructor_declaration"]) {
        let Some(body) = dtor.child_by_field_name("body") else {
            continue;
        };
        // `base.Dispose();` alone is exactly what the compiler already does.
        let inner = node_text(body, source).trim_matches(|c| c == '{' || c == '}');
        if inner.trim() == "base.Dispose();" {
            issues.push(issue(
                language,
                "S3253",
                "Remove this redundant finalizer.",
                range_of(dtor),
            ));
        }
    }
    issues
}

/// csharpsquid:S3962 — literal-initialized `static readonly` fields should be
/// `const`: their values never change at runtime.
fn is_literal_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "string_literal"
            | "verbatim_string_literal"
            | "integer_literal"
            | "real_literal"
            | "boolean_literal"
            | "character_literal"
    )
}

/// csharpsquid:S3962 — promote literal-backed static readonly fields to const.
fn check_static_readonly_literals(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["field_declaration"])
        .into_iter()
        .filter(|field| {
            let mods = modifiers_of(*field, source);
            has_modifier(&mods, "static") && has_modifier(&mods, "readonly")
        })
        .flat_map(|field| collect_kinds(field, &["variable_declarator"]))
        .filter_map(|declarator| {
            let name = declarator.child_by_field_name("name")?;
            let initializer = declarator_initializer(declarator, name)?;
            is_literal_node(initializer).then_some((declarator, initializer))
        })
        .map(|(declarator, _)| {
            issue(
                language,
                "S3962",
                "Declare this field as 'const' instead of 'static readonly'.",
                range_of(declarator),
            )
        })
        .collect()
}

/// csharpsquid:S3010 — instance constructors updating static fields leak
/// state across instances.
fn check_static_fields_updated_in_constructors(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        let static_names: std::collections::HashSet<&str> =
            static_field_declarators(type_node, source)
                .into_iter()
                .filter_map(|declarator| {
                    declarator
                        .child_by_field_name("name")
                        .map(|name| node_text(name, source))
                })
                .collect();
        if static_names.is_empty() {
            continue;
        }
        for ctor in member_declarations_of_kind(type_node, "constructor_declaration") {
            if has_modifier(&modifiers_of(ctor, source), "static") {
                continue; // static constructors are the right place
            }
            let Some(body) = ctor.child_by_field_name("body") else {
                continue;
            };
            for assignment in collect_kinds(body, &["assignment_expression"]) {
                if let Some(name) = assigned_names(assignment, source)
                    .first()
                    .filter(|name| static_names.contains(*name))
                {
                    issues.push(issue(
                        language,
                        "S3010",
                        format!(
                            "Do not assign the static field '{name}' from an instance constructor."
                        ),
                        range_of(assignment),
                    ));
                }
            }
        }
    }
    issues
}

/// csharpsquid:S2996 — `ThreadStatic` fields start uninitialized on every
/// thread; initializers run once and mislead.
fn check_thread_static_initializers(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["field_declaration"])
        .into_iter()
        .filter(|field| {
            has_any_attribute(*field, source, &["ThreadStatic", "ThreadStaticAttribute"])
        })
        .flat_map(|field| collect_kinds(field, &["variable_declarator"]))
        .filter_map(|declarator| {
            let name = declarator.child_by_field_name("name")?;
            Some((declarator, declarator_initializer(declarator, name)))
        })
        .filter(|(_, initializer)| initializer.is_some())
        .map(|(declarator, _)| {
            issue(
                language,
                "S2996",
                "Remove this initializer; '[ThreadStatic]' fields must not be initialized.",
                range_of(declarator),
            )
        })
        .collect()
}

/// csharpsquid:S3005 — `ThreadStatic` only affects static fields; on an
/// instance field it silently does nothing.
fn check_thread_static_needs_static(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["field_declaration"])
        .into_iter()
        .filter(|field| {
            has_any_attribute(*field, source, &["ThreadStatic", "ThreadStaticAttribute"])
                && !has_modifier(&modifiers_of(*field, source), "static")
        })
        .filter_map(|field| {
            collect_kinds(field, &["variable_declarator"])
                .first()
                .copied()
        })
        .filter_map(|declarator| declarator.child_by_field_name("name"))
        .map(|name_node| {
            issue(
                language,
                "S3005",
                "Mark this field 'static'; '[ThreadStatic]' applies only to static fields.",
                range_of(name_node),
            )
        })
        .collect()
}

/// csharpsquid:S2743 — static fields of generic types are shared by every
/// instantiation, which is almost never intended.
fn check_static_fields_in_generic_types(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if type_parameter_list_of(type_node).is_none() {
            continue;
        }
        for declarator in static_field_declarators(type_node, source) {
            let Some(name_node) = declarator.child_by_field_name("name") else {
                continue;
            };
            issues.push(issue(
                language,
                "S2743",
                format!(
                    "Move the static field '{}' to a non-generic type; it is shared across instantiations.",
                    node_text(name_node, source)
                ),
                range_of(name_node),
            ));
        }
    }
    issues
}

/// Whether a parameter type names an EventArgs-derived type.
fn is_event_args_parameter(parameter: Node<'_>, source: &str) -> bool {
    parameter
        .child_by_field_name("type")
        .is_some_and(|type_node| simple_name(node_text(type_node, source)).ends_with("EventArgs"))
}

/// Signature shape `(object sender, TEventArgs e)`.
fn is_event_handler_shape(delegate: Node<'_>, source: &str) -> bool {
    let parameters = parameters_of(delegate);
    parameters.len() == 2
        && parameters[0]
            .child_by_field_name("type")
            .is_some_and(|type_node| simple_name(node_text(type_node, source)) == "object")
        && is_event_args_parameter(parameters[1], source)
}

/// csharpsquid:S3906 — delegates shaped like event handlers must return void:
/// raising an event should not hand callers a result to ignore.
fn check_event_delegate_return_types(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["delegate_declaration"])
        .into_iter()
        .filter(|delegate| {
            is_event_handler_shape(*delegate, source)
                && delegate
                    .child_by_field_name("type")
                    .is_some_and(|returns| node_text(returns, source) != "void")
        })
        .filter_map(|delegate| delegate.child_by_field_name("name"))
        .map(|name_node| {
            issue(
                language,
                "S3906",
                "Change the return type of this delegate to 'void'.".to_string(),
                range_of(name_node),
            )
        })
        .collect()
}

/// csharpsquid:S3908 — custom delegates shaped like `(object, EventArgs)`
/// duplicate `EventHandler<T>`; use the framework type.
fn check_custom_event_handler_delegates(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let handler_shapes: std::collections::HashSet<&str> =
        collect_kinds(root, &["delegate_declaration"])
            .into_iter()
            .filter(|delegate| is_event_handler_shape(*delegate, source))
            .filter_map(|delegate| delegate.child_by_field_name("name"))
            .map(|name_node| node_text(name_node, source))
            .collect();
    if handler_shapes.is_empty() {
        return Vec::new();
    }
    collect_kinds(root, &["event_field_declaration"])
        .into_iter()
        .flat_map(|event_field| collect_kinds(event_field, &["variable_declaration"]))
        .filter(|declaration| {
            declaration
                .child_by_field_name("type")
                .is_some_and(|type_node| {
                    handler_shapes.contains(simple_name(node_text(type_node, source)))
                })
        })
        .flat_map(|declaration| collect_kinds(declaration, &["variable_declarator"]))
        .filter_map(|declarator| declarator.child_by_field_name("name"))
        .map(|name_node| {
            issue(
                language,
                "S3908",
                format!(
                    "Use 'EventHandler<T>' instead of this custom delegate for '{}'.",
                    node_text(name_node, source)
                ),
                range_of(name_node),
            )
        })
        .collect()
}

/// Gathers every Tier-A11 declaration contract issue.
fn declaration_contract_issues(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_partial_methods_implemented(root, source, language));
    issues.extend(check_redundant_constructors(root, source, language));
    issues.extend(check_default_field_initializers(root, source, language));
    issues.extend(check_static_fields_initialized_inline(
        root, source, language,
    ));
    issues.extend(check_static_readonly_literals(root, source, language));
    issues.extend(check_static_fields_updated_in_constructors(
        root, source, language,
    ));
    issues.extend(check_thread_static_initializers(root, source, language));
    issues.extend(check_thread_static_needs_static(root, source, language));
    issues.extend(check_static_fields_in_generic_types(root, source, language));
    issues.extend(check_event_delegate_return_types(root, source, language));
    issues.extend(check_custom_event_handler_delegates(root, source, language));
    issues.extend(check_attribute_classes_constrained(root, source, language));
    issues.extend(check_extension_methods_on_object(root, source, language));
    issues.extend(check_event_payload_types(root, source, language));
    issues.extend(check_assembly_annotations(root, source, language));
    issues.extend(check_reserved_enum_members(root, source, language));
    issues.extend(check_flags_enums_used_bitwise(root, source, language));
    issues.extend(check_flags_members_explicit_values(root, source, language));
    issues.extend(check_flags_zero_member_named_none(root, source, language));
    issues
}

/// csharpsquid:S4225 — extension methods on 'object' match everything and
/// hide real members.
fn check_extension_methods_on_object(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["method_declaration"])
        .into_iter()
        .filter_map(|method| {
            let first = parameters_of(method).first().copied()?;
            Some((method, first))
        })
        .filter(|(_, first)| node_text(*first, source).trim_start().starts_with("this"))
        .filter_map(|(method, first)| {
            // Receiver type: the token between `this` and the parameter name.
            let text = node_text(first, source)
                .trim_start()
                .strip_prefix("this")?
                .trim();
            let type_name = simple_name(text.split_whitespace().next()?);
            (type_name == "object").then_some(method)
        })
        .filter_map(|method| method.child_by_field_name("name"))
        .map(|name_node| {
            issue(
                language,
                "S4225",
                "Refactor this extension method on 'object' to extend a more specific type.",
                range_of(name_node),
            )
        })
        .collect()
}

/// csharpsquid:S4220 — events whose custom delegate payload is not an
/// EventArgs-derived type lose the framework's sender/payload conventions.
fn check_event_payload_types(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let custom_delegates: std::collections::HashMap<&str, bool> =
        collect_kinds(root, &["delegate_declaration"])
            .into_iter()
            .filter_map(|delegate| {
                let name = delegate.child_by_field_name("name")?;
                let parameters = parameters_of(delegate);
                let carries_args = parameters
                    .last()
                    .is_some_and(|parameter| is_event_args_parameter(*parameter, source));
                Some((node_text(name, source), carries_args))
            })
            .collect();
    if custom_delegates.is_empty() {
        return Vec::new();
    }
    collect_kinds(root, &["event_field_declaration"])
        .into_iter()
        .flat_map(|event_field| collect_kinds(event_field, &["variable_declaration"]))
        .filter(|declaration| {
            declaration
                .child_by_field_name("type")
                .and_then(|type_node| {
                    custom_delegates.get(simple_name(node_text(type_node, source)))
                })
                .copied()
                .is_some_and(|carries_args| !carries_args)
        })
        .filter(|declaration| {
            declaration
                .child_by_field_name("type")
                .is_some_and(|type_node| {
                    custom_delegates.contains_key(simple_name(node_text(type_node, source)))
                })
        })
        .flat_map(|declaration| collect_kinds(declaration, &["variable_declarator"]))
        .filter_map(|declarator| declarator.child_by_field_name("name"))
        .map(|name_node| {
            issue(
                language,
                "S4220",
                format!(
                    "Have the event '{}' carry an 'EventArgs'-derived payload.",
                    node_text(name_node, source)
                ),
                range_of(name_node),
            )
        })
        .collect()
}

/// csharpsquid:S3993 — attribute classes should declare `[AttributeUsage]`
/// so compilers and tooling know where they apply.
fn check_attribute_classes_constrained(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["class_declaration"])
        .into_iter()
        .filter(|class_node| base_simple_names(*class_node, source).contains(&"Attribute"))
        .filter(|class_node| {
            !has_any_attribute(
                *class_node,
                source,
                &["AttributeUsage", "AttributeUsageAttribute"],
            )
        })
        .filter_map(|class_node| class_node.child_by_field_name("name"))
        .map(|name| {
            issue(
                language,
                "S3993",
                format!(
                    "Constrain the attribute '{}' with '[AttributeUsage]'.",
                    node_text(name, source)
                ),
                range_of(name),
            )
        })
        .collect()
}

/// Whether any assembly-level (`[assembly: ...]`) attribute is present.
fn assembly_attribute_names<'a>(root: Node<'_>, source: &'a str) -> Vec<&'a str> {
    collect_kinds(root, &["global_attribute"])
        .iter()
        .flat_map(|global| collect_kinds(*global, &["attribute"]))
        .filter_map(|attribute| attribute.child_by_field_name("name"))
        .map(|name| simple_name(node_text(name, source)))
        .collect()
}

/// File-level finding anchored at the top of the file, like S1451.
fn file_level_issue(language: CsLanguage, rule: &str, message: &str) -> Issue {
    issue(
        language,
        rule,
        message,
        hoonarqube_ir::Range {
            start: hoonarqube_ir::Pos { line: 1, column: 0 },
            end: hoonarqube_ir::Pos { line: 1, column: 0 },
        },
    )
}

/// Assembly-annotation presence checks (csharpsquid:S3990, S3992, S4026).
/// Files without any assembly attributes are not treated as assembly-info
/// files and stay clean; a file annotating some but not all of the trio is
/// flagged for the missing ones.
fn check_assembly_annotations(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let names = assembly_attribute_names(root, source);
    if names.is_empty() {
        return Vec::new();
    }
    let has = |wanted: &[&str]| names.iter().any(|name| wanted.contains(name));
    let mut issues = Vec::new();
    if !has(&["CLSCompliant", "CLSCompliantAttribute"]) {
        issues.push(file_level_issue(
            language,
            "S3990",
            "Annotate this assembly with '[assembly: CLSCompliant]'.",
        ));
    }
    if !has(&["ComVisible", "ComVisibleAttribute"]) {
        issues.push(file_level_issue(
            language,
            "S3992",
            "Annotate this assembly with '[assembly: ComVisible]'.",
        ));
    }
    if !has(&[
        "NeutralResourcesLanguage",
        "NeutralResourcesLanguageAttribute",
    ]) {
        issues.push(file_level_issue(
            language,
            "S4026",
            "Annotate this assembly with '[assembly: NeutralResourcesLanguage]'.",
        ));
    }
    issues
}

/// csharpsquid:S4016 — members named 'Reserved' promise nothing and invite
/// cargo-cult extensions.
fn check_reserved_enum_members(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["enum_declaration"])
        .into_iter()
        .flat_map(|enum_node| collect_kinds(enum_node, &["enum_member_declaration"]))
        .filter_map(|member| member.child_by_field_name("name"))
        .filter(|name| node_text(*name, source).eq_ignore_ascii_case("reserved"))
        .map(|name| {
            issue(
                language,
                "S4016",
                "Rename this 'Reserved' enumeration member.",
                range_of(name),
            )
        })
        .collect()
}

/// Whether any binary or compound-assignment expression in the file applies
/// a bitwise operator (`&`, `|`, `^`, `|=`, `&=`, `^=`); `&&`/`||` stay
/// logical.
fn file_uses_bitwise_operators(root: Node<'_>, source: &str) -> bool {
    for expr in collect_kinds(root, &["binary_expression", "assignment_expression"]) {
        let bytes = node_text(expr, source).as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            match bytes[index] {
                b'|' | b'&' => {
                    let doubled = bytes.get(index + 1) == Some(&bytes[index]);
                    if !doubled {
                        return true;
                    }
                    index += 1;
                }
                b'^' => return true,
                _ => {}
            }
            index += 1;
        }
    }
    false
}

/// csharpsquid:S4070 — '[Flags]' on enumerations nobody combines bitwise is
/// misleading decoration.
fn check_flags_enums_used_bitwise(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    if file_uses_bitwise_operators(root, source) {
        return Vec::new();
    }
    collect_kinds(root, &["enum_declaration"])
        .into_iter()
        .filter(|enum_node| enum_has_flags_attribute(*enum_node, source))
        .filter_map(|enum_node| enum_node.child_by_field_name("name"))
        .map(|name| {
            issue(
                language,
                "S4070",
                "Remove '[Flags]' from this enumeration or apply bitwise operations to it.",
                range_of(name),
            )
        })
        .collect()
}

/// Members of a flags enumeration with their explicit value nodes.
fn enum_members(enum_node: Node<'_>) -> Vec<(Node<'_>, Option<Node<'_>>)> {
    collect_kinds(enum_node, &["enum_member_declaration"])
        .into_iter()
        .map(|member| (member, member.child_by_field_name("value")))
        .collect()
}

/// csharpsquid:S2345 — '[Flags]' members without explicit values get
/// powers-of-two-unfriendly implicit numbering.
fn check_flags_members_explicit_values(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["enum_declaration"])
        .into_iter()
        .filter(|enum_node| enum_has_flags_attribute(*enum_node, source))
        .flat_map(|enum_node| enum_members(enum_node))
        .filter_map(|(member, value)| {
            let name = member.child_by_field_name("name")?;
            value.is_none().then_some(name)
        })
        .map(|name| {
            issue(
                language,
                "S2345",
                format!(
                    "Give the enumeration member '{}' an explicit value.",
                    node_text(name, source)
                ),
                range_of(name),
            )
        })
        .collect()
}

/// csharpsquid:S2346 — the zero value of a '[Flags]' enumeration means 'no
/// options' and should be named 'None'.
fn check_flags_zero_member_named_none(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["enum_declaration"])
        .into_iter()
        .filter(|enum_node| enum_has_flags_attribute(*enum_node, source))
        .flat_map(|enum_node| {
            let members = enum_members(enum_node);
            // Explicit zero wins; otherwise an uninitialized first member is
            // implicitly zero.
            let zero = members.iter().find_map(|(_, value)| {
                value
                    .and_then(|node| integer_literal_value(node_text(node, source)))
                    .filter(|parsed| *parsed == 0)
            });
            let zero_member = zero.and_then(|_| {
                members.iter().find(|(_, value)| {
                    value.and_then(|node| integer_literal_value(node_text(node, source))) == Some(0)
                })
            });
            let candidate = match (zero_member, members.first()) {
                (Some((_, _)), _) => Some(zero_member.unwrap().0),
                (None, Some((first, None))) if members.len() > 1 => Some(*first),
                _ => None,
            };
            candidate.into_iter()
        })
        .filter_map(|member| member.child_by_field_name("name"))
        .filter(|name| !node_text(*name, source).eq_ignore_ascii_case("none"))
        .map(|name| {
            issue(
                language,
                "S2346",
                format!(
                    "Name this zero-valued '[Flags]' member '{}' 'None' instead.",
                    node_text(name, source)
                ),
                range_of(name),
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// A12 — security textual deny/require lists
// ---------------------------------------------------------------------------

/// The declaration an attribute decorates (`attribute` → `attribute_list` →
/// declaration). Assembly-level attributes have no declaration.
fn attributed_declaration(attribute: Node<'_>) -> Option<Node<'_>> {
    attribute
        .parent()
        .filter(|list| list.kind() == "attribute_list")
        .and_then(|list| list.parent())
}

/// Return-type spelling of a callable (`void`, `Task<int>`, ...); the field
/// carrying it differs between declaration kinds.
fn return_type_text<'a>(callable: Node<'_>, source: &'a str) -> &'a str {
    for field in ["returns", "type"] {
        if let Some(return_type) = callable.child_by_field_name(field) {
            return node_text(return_type, source);
        }
    }
    ""
}

/// csharpsquid:S3597 — `[OperationContract]` methods belong to
/// `[ServiceContract]` types.
fn check_operation_contract_pairing(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (name, _, attribute) in attribute_applications(root, source) {
        if !matches!(name, "OperationContract" | "OperationContractAttribute") {
            continue;
        }
        let Some(method) = attributed_declaration(attribute) else {
            continue;
        };
        if method.kind() != "method_declaration" {
            continue;
        }
        let contracted = enclosing_type(method)
            .is_some_and(|ty| has_any_attribute(ty, source, &["ServiceContract"]));
        if !contracted {
            issues.push(issue(
                language,
                "S3597",
                "Use '[OperationContract]' only on methods of a '[ServiceContract]' type.",
                range_of(attribute),
            ));
        }
    }
    issues
}

/// csharpsquid:S3598 — one-way operations cannot report a result.
fn check_one_way_contracts_return_void(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (name, args, attribute) in attribute_applications(root, source) {
        if !matches!(name, "OperationContract" | "OperationContractAttribute") {
            continue;
        }
        let Some(args) = args else { continue };
        let args_text = node_text(args, source);
        if !(args_text.contains("IsOneWay") && args_text.contains("true")) {
            continue;
        }
        let Some(method) = attributed_declaration(attribute) else {
            continue;
        };
        if method.kind() == "method_declaration" && return_type_text(method, source) != "void" {
            issues.push(issue(
                language,
                "S3598",
                "Remove 'IsOneWay' from this operation or make it return void.",
                range_of(attribute),
            ));
        }
    }
    issues
}

/// csharpsquid:S3603 — methods annotated '[Pure]' must return a value.
fn check_pure_methods_return_values(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (name, _, attribute) in attribute_applications(root, source) {
        if !matches!(name, "Pure" | "PureAttribute") {
            continue;
        }
        let Some(method) = attributed_declaration(attribute) else {
            continue;
        };
        if method.kind() == "method_declaration" && return_type_text(method, source) == "void" {
            issues.push(issue(
                language,
                "S3603",
                "Methods annotated '[Pure]' must return a value.",
                range_of(attribute),
            ));
        }
    }
    issues
}

/// csharpsquid:S4210 — `WinForms` entry points are marked `[STAThread]`.
fn check_winforms_entry_points(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let winforms_file =
        source.contains("System.Windows.Forms") || source.contains("Application.Run");
    if !winforms_file {
        return Vec::new();
    }
    collect_kinds(root, &["method_declaration"])
        .into_iter()
        .filter(|method| !is_error_tainted(*method))
        .filter(|method| {
            method
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source) == "Main")
        })
        .filter(|method| !has_any_attribute(*method, source, &["STAThread"]))
        .map(|method| {
            issue(
                language,
                "S4210",
                "Mark the WinForms entry point with '[STAThread]'.",
                range_of(name_anchor(method)),
            )
        })
        .collect()
}

/// csharpsquid:S4211 — the two transparency levels contradict each other.
fn check_conflicting_transparency_attributes(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if is_error_tainted(type_node) {
            continue;
        }
        let attributes = attributes_of(type_node, source);
        if has_attribute(&attributes, "SecurityCritical")
            && has_attribute(&attributes, "SecuritySafeCritical")
        {
            issues.push(issue(
                language,
                "S4211",
                "Apply either 'SecurityCritical' or 'SecuritySafeCritical', not both.",
                range_of(type_node),
            ));
        }
    }
    issues
}

/// csharpsquid:S4212 — serialization constructors stay hidden from callers.
fn check_serialization_constructors_secured(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    const SERIALIZATION_PARAM_TYPES: [&str; 2] = ["SerializationInfo", "StreamingContext"];
    let mut issues = Vec::new();
    for constructor in collect_kinds(root, &["constructor_declaration"]) {
        if is_error_tainted(constructor) {
            continue;
        }
        let param_types: Vec<String> = parameters_of(constructor)
            .into_iter()
            .filter_map(|param| param.child_by_field_name("type"))
            .map(|ty| simple_name(node_text(ty, source)).to_string())
            .collect();
        if !SERIALIZATION_PARAM_TYPES
            .iter()
            .all(|wanted| param_types.iter().any(|found| found == wanted))
        {
            continue;
        }
        let modifiers = modifiers_of(constructor, source);
        let family_visible = has_modifier(&modifiers, "protected");
        let exposed = has_modifier(&modifiers, "public")
            || (has_modifier(&modifiers, "internal") && !family_visible);
        if exposed {
            issues.push(issue(
                language,
                "S4212",
                "Reduce the visibility of this serialization constructor.",
                range_of(constructor),
            ));
        }
    }
    issues
}

/// csharpsquid:S3926 — `[OptionalField]` members need an `[OnDeserialized]`
/// hook to repair data written by older versions.
fn check_optional_fields_have_deserialization_hooks(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for field in collect_kinds(root, &["field_declaration"]) {
        if is_error_tainted(field) || !has_any_attribute(field, source, &["OptionalField"]) {
            continue;
        }
        let hooked = enclosing_type(field).is_some_and(|ty| {
            member_declarations_of_kind(ty, "method_declaration")
                .iter()
                .any(|method| has_any_attribute(*method, source, &["OnDeserialized"]))
        });
        if !hooked {
            issues.push(issue(
                language,
                "S3926",
                "Handle this '[OptionalField]' member in an '[OnDeserialized]' callback.",
                range_of(field),
            ));
        }
    }
    issues
}

/// csharpsquid:S3927 — serialization callbacks return void and take exactly
/// one `StreamingContext`.
fn check_serialization_event_handler_shapes(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    const SERIALIZATION_EVENT_ATTRIBUTES: [&str; 4] = [
        "OnSerializing",
        "OnDeserializing",
        "OnSerialized",
        "OnDeserialized",
    ];
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method)
            || !has_any_attribute(method, source, &SERIALIZATION_EVENT_ATTRIBUTES)
        {
            continue;
        }
        let parameters = parameters_of(method);
        let context_parameter = parameters
            .first()
            .and_then(|param| param.child_by_field_name("type"));
        let shape_ok = return_type_text(method, source) == "void"
            && parameters.len() == 1
            && context_parameter
                .is_some_and(|ty| simple_name(node_text(ty, source)) == "StreamingContext");
        if !shape_ok {
            issues.push(issue(
                language,
                "S3927",
                "Serialization callbacks return void and take exactly one 'StreamingContext'.",
                range_of(method),
            ));
        }
    }
    issues
}

/// `argument` wrapper nodes of an invocation or object creation; the
/// wrappers live one level down inside the `argument_list`.
fn call_argument_nodes(call: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = call.walk();
    call.children(&mut cursor)
        .find(|child| child.kind() == "argument_list")
        .map(argument_nodes)
        .unwrap_or_default()
}

/// csharpsquid:S3928 — the 'paramName' argument must name a parameter that
/// actually exists on the throwing method.
fn check_argument_exception_param_names(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    const ARGUMENT_EXCEPTION_TYPES: [&str; 3] = [
        "ArgumentException",
        "ArgumentNullException",
        "ArgumentOutOfRangeException",
    ];
    let mut issues = Vec::new();
    for creation in collect_kinds(root, &["object_creation_expression"]) {
        if is_error_tainted(creation) {
            continue;
        }
        if !ARGUMENT_EXCEPTION_TYPES.contains(&simple_name(creation_type_text(creation, source))) {
            continue;
        }
        let arguments = call_argument_nodes(creation);
        if arguments.len() < 2 {
            continue;
        }
        let value = argument_expression(arguments[1]);
        if value.kind() != "string_literal" {
            continue;
        }
        let wanted = literal_inner_text(value, source);
        let Some(method) = enclosing_method(creation) else {
            continue;
        };
        let known = parameters_of(method).iter().any(|param| {
            param
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source) == wanted)
        });
        if !known {
            issues.push(issue(
                language,
                "S3928",
                "Pass an existing parameter name to this exception.",
                range_of(creation),
            ));
        }
    }
    issues
}

/// csharpsquid:S4581 — `new Guid()` yields all zeros; only `Guid.NewGuid`
/// produces a real identity.
fn check_empty_guid_creations(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for creation in collect_kinds(root, &["object_creation_expression"]) {
        if is_error_tainted(creation) {
            continue;
        }
        if simple_name(creation_type_text(creation, source)) == "Guid"
            && call_argument_nodes(creation).is_empty()
        {
            issues.push(issue(
                language,
                "S4581",
                "Generate a new GUID instead of relying on the empty value.",
                range_of(creation),
            ));
        }
    }
    issues
}

/// csharpsquid:S4260 — `[ConstructorArgument]` names must exist as parameters
/// of a constructor of the same class.
fn check_constructor_argument_names(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (name, args, attribute) in attribute_applications(root, source) {
        if !matches!(name, "ConstructorArgument" | "ConstructorArgumentAttribute") {
            continue;
        }
        let Some(args) = args else { continue };
        let literals = collect_kinds(args, &["string_literal"]);
        let Some(literal) = literals.first() else {
            continue;
        };
        let wanted = literal_inner_text(*literal, source);
        let Some(member) = attributed_declaration(attribute) else {
            continue;
        };
        if !matches!(member.kind(), "property_declaration" | "field_declaration") {
            continue;
        }
        let supplied = enclosing_type(member).is_some_and(|ty| {
            collect_kinds(ty, &["constructor_declaration"])
                .iter()
                .any(|ctor| {
                    parameters_of(*ctor).iter().any(|param| {
                        param
                            .child_by_field_name("name")
                            .is_some_and(|param_name| node_text(param_name, source) == wanted)
                    })
                })
        });
        if !supplied {
            issues.push(issue(
                language,
                "S4260",
                "Match this '[ConstructorArgument]' name with a declared constructor parameter.",
                range_of(attribute),
            ));
        }
    }
    issues
}

/// Identifier nodes spelling one of `names`, ignoring using directives where
/// the name merely imports a namespace.
fn identifier_usages<'t>(root: Node<'t>, source: &str, names: &[&str]) -> Vec<Node<'t>> {
    collect_kinds(root, &["identifier"])
        .into_iter()
        .filter(|node| !is_error_tainted(*node))
        .filter(|node| names.contains(&node_text(*node, source)))
        .filter(|node| {
            node.parent()
                .is_none_or(|parent| parent.kind() != "using_directive")
        })
        .collect()
}

/// csharpsquid:S4428 — `[PartCreationPolicy]` is meaningless without
/// '[Export]'.
fn check_part_creation_policy_needs_export(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if is_error_tainted(type_node) {
            continue;
        }
        let attributes = attributes_of(type_node, source);
        if has_attribute(&attributes, "PartCreationPolicy") && !has_attribute(&attributes, "Export")
        {
            issues.push(issue(
                language,
                "S4428",
                "Add an '[Export]' attribute next to this '[PartCreationPolicy]'.",
                range_of(type_node),
            ));
        }
    }
    issues
}

/// csharpsquid:S4423 — deprecated SSL/TLS protocol versions invite downgrade
/// attacks; negotiate 'Tls12' or 'Tls13'.
fn check_weak_ssl_protocols(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let ssl_protocol_accesses = banned_member_accesses(
        root,
        source,
        "SslProtocols",
        &["Ssl2", "Ssl3", "Tls", "Tls10", "Tls11"],
    );
    let security_protocol_accesses =
        banned_member_accesses(root, source, "SecurityProtocolType", &["Ssl3", "Tls"]);
    ssl_protocol_accesses
        .into_iter()
        .chain(security_protocol_accesses)
        .map(|access| {
            issue(
                language,
                "S4423",
                "Negotiate 'Tls12' or 'Tls13' instead of this deprecated protocol.",
                range_of(access),
            )
        })
        .collect()
}

/// csharpsquid:S4790 — 'MD5' and 'SHA1' are broken for security purposes.
fn check_weak_hash_algorithms(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const WEAK_HASH_TYPES: [&str; 9] = [
        "MD5",
        "HMACMD5",
        "MD5CryptoServiceProvider",
        "MD5Cng",
        "SHA1",
        "HMACSHA1",
        "SHA1CryptoServiceProvider",
        "SHA1Cng",
        "SHA1Managed",
    ];
    identifier_usages(root, source, &WEAK_HASH_TYPES)
        .into_iter()
        .map(|identifier| {
            issue(
                language,
                "S4790",
                "Use a stronger hash algorithm such as 'SHA256'.",
                range_of(identifier),
            )
        })
        .collect()
}

/// csharpsquid:S5542 — unauthenticated modes and zero padding leak or forge
/// plaintext.
fn check_insecure_cipher_modes(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mode_accesses = banned_member_accesses(root, source, "CipherMode", &["ECB", "OFB", "CFB"]);
    let padding_accesses = banned_member_accesses(root, source, "PaddingMode", &["None", "Zeros"]);
    mode_accesses
        .into_iter()
        .chain(padding_accesses)
        .map(|access| {
            issue(
                language,
                "S5542",
                "Encrypt with an authenticated cipher mode and explicit padding.",
                range_of(access),
            )
        })
        .collect()
}

/// csharpsquid:S5547 — legacy block ciphers belong in museums, not code.
fn check_robust_ciphers_required(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const WEAK_CIPHER_PROVIDERS: [&str; 7] = [
        "DES",
        "TripleDES",
        "RC2",
        "RC4",
        "DESCryptoServiceProvider",
        "TripleDESCryptoServiceProvider",
        "RC2CryptoServiceProvider",
    ];
    identifier_usages(root, source, &WEAK_CIPHER_PROVIDERS)
        .into_iter()
        .map(|identifier| {
            issue(
                language,
                "S5547",
                "Use a robust cipher such as 'Aes' instead of this provider.",
                range_of(identifier),
            )
        })
        .collect()
}

/// csharpsquid:S4426 — weak asymmetric providers and short keys give way.
fn check_cryptographic_keys_robust(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    const WEAK_ASYMMETRIC_PROVIDERS: [&str; 2] =
        ["RSACryptoServiceProvider", "DSACryptoServiceProvider"];
    const MINIMUM_ASYMMETRIC_KEY_SIZE: u64 = 2048;
    let mut issues: Vec<Issue> = identifier_usages(root, source, &WEAK_ASYMMETRIC_PROVIDERS)
        .into_iter()
        .map(|identifier| {
            issue(
                language,
                "S4426",
                "Generate this key with 'RSA.Create' at 2048 bits or more.",
                range_of(identifier),
            )
        })
        .collect();
    for assignment in collect_kinds(root, &["assignment_expression"]) {
        if is_error_tainted(assignment) || operator_of(assignment) != Some("=") {
            continue;
        }
        let Some((target, value)) = binary_operands(assignment) else {
            continue;
        };
        if !node_text(target, source).ends_with("KeySize") || value.kind() != "integer_literal" {
            continue;
        }
        let undersized = integer_literal_value(node_text(value, source))
            .is_some_and(|bits| bits < MINIMUM_ASYMMETRIC_KEY_SIZE);
        if undersized {
            issues.push(issue(
                language,
                "S4426",
                "Keep cryptographic keys at 2048 bits or more.",
                range_of(assignment),
            ));
        }
    }
    issues
}

/// csharpsquid:S5659 — JWTs signed or accepted with 'none'/weak HMAC
/// algorithms can be forged by anyone.
fn check_jwt_strong_algorithms(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const WEAK_JWT_ALGORITHMS: [&str; 4] = ["none", "HS256", "HS384", "HS512"];
    let jwt_context_tokens = ["Jwt", "TokenValidation", "SigningCredentials"];
    let mut issues = Vec::new();
    for literal in string_literals(root) {
        if is_error_tainted(literal) {
            continue;
        }
        let algorithm = literal_inner_text(literal, source);
        if !WEAK_JWT_ALGORITHMS.contains(&algorithm) {
            continue;
        }
        let call_context = ancestors_of(literal).find(|ancestor| {
            matches!(
                ancestor.kind(),
                "invocation_expression" | "object_creation_expression"
            )
        });
        let jwt_context = call_context.is_some_and(|call| {
            let text = node_text(call, source);
            jwt_context_tokens.iter().any(|token| text.contains(token))
        });
        if jwt_context {
            issues.push(issue(
                language,
                "S5659",
                "Sign and verify JWTs with a strong algorithm such as 'RS256'.",
                range_of(literal),
            ));
        }
    }
    issues
}

/// csharpsquid:S5332 — clear-text channels expose everything they carry;
/// namespace schemas and loopback addresses are exempt.
fn check_clear_text_protocols(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const EXEMPT_MARKERS: [&str; 4] = ["://localhost", "127.0.0.1", "www.w3.org", "schemas."];
    let mut issues = Vec::new();
    for literal in string_literals(root) {
        if is_error_tainted(literal) {
            continue;
        }
        let lowered = literal_inner_text(literal, source).to_ascii_lowercase();
        let clear_text = (lowered.contains("http://") || lowered.contains("ws://"))
            && !EXEMPT_MARKERS.iter().any(|marker| lowered.contains(marker));
        if clear_text {
            issues.push(issue(
                language,
                "S5332",
                "Serve this connection over an encrypted channel instead.",
                range_of(literal),
            ));
        }
    }
    issues
}

/// csharpsquid:S5443 — publicly writable directories let any local user swap
/// the files you just wrote.
fn check_publicly_writable_temp_paths(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    const PUBLIC_TEMP_MARKERS: [&str; 4] = ["/tmp/", "/var/tmp", "%temp%", "\\windows\\temp"];
    let mut issues = Vec::new();
    for literal in string_literals(root) {
        if is_error_tainted(literal) {
            continue;
        }
        let lowered = literal_inner_text(literal, source).to_ascii_lowercase();
        if PUBLIC_TEMP_MARKERS
            .iter()
            .any(|marker| lowered.contains(marker))
        {
            issues.push(issue(
                language,
                "S5443",
                "Do not place files in publicly writable directories.",
                range_of(literal),
            ));
        }
    }
    issues
}

/// csharpsquid:S5445 — predictable temporary file names let attackers pre-
/// create the path and hijack the write.
fn check_predictable_temp_files(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| {
            invocation_targets(*invocation, source, Some("Path"), &["GetTempFileName"])
        })
        .map(|invocation| {
            issue(
                language,
                "S5445",
                "Create temporary files with unpredictable names in a private directory.",
                range_of(invocation),
            )
        })
        .collect()
}

/// csharpsquid:S4507 — shipping with debugging enabled hands attackers a
/// detailed map of the application.
fn check_debugging_left_enabled(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for literal in string_literals(root) {
        if is_error_tainted(literal) {
            continue;
        }
        let lowered = literal_inner_text(literal, source).to_ascii_lowercase();
        let debug_on = (lowered.contains("customerrors") && lowered.contains("off"))
            || (lowered.contains("debug=") && lowered.contains("true"));
        if debug_on {
            issues.push(issue(
                language,
                "S4507",
                "Disable debugging features in production.",
                range_of(literal),
            ));
        }
    }
    issues
}

/// csharpsquid:S5753 — disabling request validation reopens the XSS door.
fn check_request_validation_disabled(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for literal in string_literals(root) {
        if is_error_tainted(literal) {
            continue;
        }
        let lowered = literal_inner_text(literal, source).to_ascii_lowercase();
        if lowered.contains("validaterequest") && lowered.contains("false") {
            issues.push(issue(
                language,
                "S5753",
                "Keep ASP.NET request validation enabled.",
                range_of(literal),
            ));
        }
    }
    for invocation in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(invocation)
            || !invocation_targets(invocation, source, None, &["ValidateInput"])
        {
            continue;
        }
        let disables = invocation_arguments(invocation)
            .iter()
            .any(|argument| node_text(*argument, source) == "false");
        if disables {
            issues.push(issue(
                language,
                "S5753",
                "Keep ASP.NET request validation enabled.",
                range_of(invocation),
            ));
        }
    }
    issues
}

/// csharpsquid:S4502 — turning antiforgery off invites cross-site request
/// forgery.
fn check_antiforgery_disabled(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["assignment_expression"])
        .into_iter()
        .filter(|assignment| !is_error_tainted(*assignment))
        .filter(|assignment| operator_of(*assignment) == Some("="))
        .filter(|assignment| {
            binary_operands(*assignment).is_some_and(|(target, value)| {
                node_text(target, source)
                    .to_ascii_lowercase()
                    .contains("ntiforgery")
                    && value.kind() == "boolean_literal"
                    && node_text(value, source) == "false"
            })
        })
        .map(|assignment| {
            issue(
                language,
                "S4502",
                "Keep antiforgery validation enabled.",
                range_of(assignment),
            )
        })
        .collect()
}

/// csharpsquid:S5773 — `TypeNameHandling` beyond `None` lets payloads name
/// arbitrary types to instantiate.
fn check_unrestricted_deserialization(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    banned_member_accesses(
        root,
        source,
        "TypeNameHandling",
        &["All", "Auto", "Objects", "Arrays"],
    )
    .into_iter()
    .map(|access| {
        issue(
            language,
            "S5773",
            "Restrict deserialization by keeping 'TypeNameHandling' at 'None'.",
            range_of(access),
        )
    })
    .collect()
}

/// csharpsquid:S5042 — unbounded archive extraction grinds the host down
/// with zip bombs.
fn check_unbounded_archive_extraction(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    const EXTRACTION_METHODS: [&str; 2] = ["ExtractToDirectory", "ExtractToFile"];
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| {
            callee_name(*invocation, source).is_some_and(|name| EXTRACTION_METHODS.contains(&name))
        })
        .map(|invocation| {
            issue(
                language,
                "S5042",
                "Bound this archive extraction before running it.",
                range_of(invocation),
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// A13 — date/time & Azure/ASP.NET textual heuristics
// ---------------------------------------------------------------------------

/// csharpsquid:S6354 — the system clock is untestable; inject a time
/// provider instead of reading `DateTime` statics.
fn check_direct_datetime_usage(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    banned_member_accesses(root, source, "DateTime", &["Now", "UtcNow", "Today"])
        .into_iter()
        .map(|access| {
            issue(
                language,
                "S6354",
                "Inject a testable time provider instead of reading the system clock.",
                range_of(access),
            )
        })
        .collect()
}

/// csharpsquid:S6561 — timing measurements belong to `Stopwatch`, not wall
/// clock reads that jump with timezone or NTP changes.
fn check_datetime_now_for_timing(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["method_declaration"])
        .into_iter()
        .filter(|method| !is_error_tainted(*method))
        .filter_map(|method| body_of(method).map(|body| (method, body)))
        .filter(|(_, body)| mentions_identifier_outside_parameter_list(*body, "Stopwatch", source))
        .flat_map(|(_, body)| banned_member_accesses(body, source, "DateTime", &["Now", "Today"]))
        .map(|access| {
            issue(
                language,
                "S6561",
                "Measure elapsed time with 'Stopwatch' instead of 'DateTime.Now'.",
                range_of(access),
            )
        })
        .collect()
}

/// The `argument` expressions of a `new T(...)` creation.
fn creation_argument_expressions(creation: Node<'_>) -> Vec<Node<'_>> {
    call_argument_nodes(creation)
        .iter()
        .copied()
        .map(argument_expression)
        .collect()
}

/// csharpsquid:S6562 — `DateTime` values without an explicit
/// `DateTimeKind` flip meaning across timezones and DST boundaries.
fn check_datetime_kind_specified(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for creation in collect_kinds(root, &["object_creation_expression"]) {
        if is_error_tainted(creation)
            || simple_name(creation_type_text(creation, source)) != "DateTime"
        {
            continue;
        }
        let arguments = creation_argument_expressions(creation);
        let kind_specified = arguments
            .iter()
            .any(|argument| node_text(*argument, source).contains("DateTimeKind"));
        if !kind_specified {
            issues.push(issue(
                language,
                "S6562",
                "Specify the 'DateTimeKind' when constructing this value.",
                range_of(creation),
            ));
        }
    }
    issues
}

/// csharpsquid:S6588 — the Unix epoch literal spells `UnixEpoch`.
fn check_unix_epoch_literal(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const EPOCH_COMPONENTS: [u64; 3] = [1970, 1, 1];
    let mut issues = Vec::new();
    for creation in collect_kinds(root, &["object_creation_expression"]) {
        if is_error_tainted(creation)
            || simple_name(creation_type_text(creation, source)) != "DateTime"
        {
            continue;
        }
        let arguments = creation_argument_expressions(creation);
        if arguments.len() < 3 {
            continue;
        }
        let matches_epoch = EPOCH_COMPONENTS.iter().enumerate().all(|(index, wanted)| {
            arguments[index].kind() == "integer_literal"
                && integer_literal_value(node_text(arguments[index], source)) == Some(*wanted)
        });
        if matches_epoch {
            issues.push(issue(
                language,
                "S6588",
                "Use 'DateTimeOffset.UnixEpoch' instead of this literal.",
                range_of(creation),
            ));
        }
    }
    issues
}

/// csharpsquid:S6575 — Windows time-zone ids vanish on other platforms;
/// `TimeZoneConverter` translates them safely.
fn check_find_system_time_zone_without_converter(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    if source.contains("TimeZoneConverter") {
        return Vec::new();
    }
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| {
            invocation_targets(
                *invocation,
                source,
                Some("TimeZoneInfo"),
                &["FindSystemTimeZoneById"],
            )
        })
        .map(|invocation| {
            issue(
                language,
                "S6575",
                "Resolve time zones through 'TimeZoneConverter' for portability.",
                range_of(invocation),
            )
        })
        .collect()
}

/// csharpsquid:S6580 — parsing dates without a format provider silently
/// adopts the machine's culture.
fn check_culture_less_date_parsing(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    const CULTURE_ARGUMENT_MARKERS: [&str; 2] = ["CultureInfo", "IFormatProvider"];
    const PARSING_TARGETS: [&str; 4] = ["Parse", "ParseExact", "TryParse", "ToDateTime"];
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| {
            invocation_targets(*invocation, source, None, &PARSING_TARGETS)
                || invocation_targets(*invocation, source, Some("DateTime"), &PARSING_TARGETS)
                || invocation_targets(*invocation, source, Some("Convert"), &PARSING_TARGETS)
        })
        .filter(|invocation| {
            !invocation_arguments(*invocation).iter().any(|argument| {
                let text = node_text(*argument, source);
                CULTURE_ARGUMENT_MARKERS
                    .iter()
                    .any(|marker| text.contains(marker))
            })
        })
        .map(|invocation| {
            issue(
                language,
                "S6580",
                "Pass an explicit culture when parsing this date or time.",
                range_of(invocation),
            )
        })
        .collect()
}

/// csharpsquid:S6585 — hard-coded date format strings ignore the user's
/// culture; pass a provider or use the invariant one deliberately.
fn check_hardcoded_date_formats(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    /// Distinctive date/time pattern tokens (`MM` differs from `mm`).
    const DATE_FORMAT_TOKENS: [&str; 12] = [
        "yyyy", "yyy", "MMMM", "MMM", "dddd", "ddd", "MM", "dd", "HH", "hh", "mm", "ss",
    ];
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| callee_name(*invocation, source) == Some("ToString"))
        .filter_map(|invocation| invocation_arguments(invocation).first().copied())
        .map(argument_expression)
        .filter(|argument| argument.kind() == "string_literal")
        .filter(|argument| {
            let text = literal_inner_text(*argument, source);
            DATE_FORMAT_TOKENS.iter().any(|token| text.contains(token))
        })
        .map(|argument| {
            issue(
                language,
                "S6585",
                "Format this date with an explicit culture-aware provider.",
                range_of(argument),
            )
        })
        .collect()
}
/// Methods attributed `[Function]` or `[FunctionName]` (Azure Functions).
fn azure_function_methods<'t>(root: Node<'t>, source: &str) -> Vec<Node<'t>> {
    collect_kinds(root, &["method_declaration"])
        .into_iter()
        .filter(|method| !is_error_tainted(*method))
        .filter(|method| has_any_attribute(*method, source, &["Function", "FunctionName"]))
        .collect()
}

/// csharpsquid:S6419 — mutable instance state leaks across parallel Azure
/// Function invocations.
fn check_azure_function_instance_state(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        let hosts_function = member_declarations_of_kind(type_node, "method_declaration")
            .iter()
            .any(|method| has_any_attribute(*method, source, &["Function", "FunctionName"]));
        if !hosts_function {
            continue;
        }
        for field in member_declarations_of_kind(type_node, "field_declaration") {
            if is_error_tainted(field) {
                continue;
            }
            let modifiers = modifiers_of(field, source);
            let immutable = has_modifier(&modifiers, "static")
                || has_modifier(&modifiers, "readonly")
                || has_modifier(&modifiers, "const");
            if !immutable {
                issues.push(issue(
                    language,
                    "S6419",
                    "Keep this class stateless; do not hold mutable instance fields.",
                    range_of(field),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S6421 — unhandled exceptions in a Function surface as raw
/// 500s; failures belong in a try/catch.
fn check_azure_functions_catch_failures(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    azure_function_methods(root, source)
        .into_iter()
        .filter(|method| body_of(*method).is_some_and(|body| body.kind() == "block"))
        .filter(|method| {
            !subtree_contains_kind(body_of(*method).unwrap_or(*method), "try_statement")
        })
        .map(|method| {
            issue(
                language,
                "S6421",
                "Wrap this Function in a try/catch and report the failure.",
                range_of(name_anchor(method)),
            )
        })
        .collect()
}

/// Types hosting at least one Azure Function method.
fn azure_function_classes<'t>(root: Node<'t>, source: &str) -> Vec<Node<'t>> {
    collect_kinds(root, &TYPE_DECLARATION_KINDS)
        .into_iter()
        .filter(|type_node| {
            member_declarations_of_kind(*type_node, "method_declaration")
                .iter()
                .any(|method| has_any_attribute(*method, source, &["Function", "FunctionName"]))
        })
        .collect()
}

/// Blocking member accesses and calls nested inside `scope`.
fn blocking_calls_in_scope<'t>(scope: Node<'t>, source: &str) -> Vec<Node<'t>> {
    let accesses = collect_kinds(scope, &["member_access_expression"])
        .into_iter()
        .filter(|access| !is_error_tainted(*access))
        .filter(|access| {
            matches!(
                expression_name(*access, source).unwrap_or(""),
                "Result" | "Wait"
            )
        });
    let get_results = collect_kinds(scope, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| callee_name(*invocation, source) == Some("GetResult"));
    accesses.chain(get_results).collect()
}

/// csharpsquid:S6422 — blocking on async work inside a Function deadlocks
/// the single-invocation host.
fn check_azure_functions_do_not_block(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    azure_function_classes(root, source)
        .into_iter()
        .flat_map(|class_node| blocking_calls_in_scope(class_node, source))
        .map(|call| {
            issue(
                language,
                "S6422",
                "Await async work instead of blocking inside an Azure Function.",
                range_of(call),
            )
        })
        .collect()
}

/// csharpsquid:S6423 — swallowed failures in a Function vanish from view;
/// every catch must log.
fn check_azure_catches_log_failures(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    const LOGGING_MARKERS: [&str; 3] = ["Log", "_log", "logger"];
    azure_function_classes(root, source)
        .iter()
        .flat_map(|class_node| collect_kinds(*class_node, &["catch_clause"]))
        .filter(|catch_clause| !is_error_tainted(*catch_clause))
        .filter(|catch_clause| {
            let text = node_text(*catch_clause, source);
            !LOGGING_MARKERS.iter().any(|marker| text.contains(marker))
        })
        .map(|catch_clause| {
            issue(
                language,
                "S6423",
                "Log the failure inside this catch block.",
                range_of(catch_clause),
            )
        })
        .collect()
}

/// csharpsquid:S6420 — per-invocation client construction burns sockets and
/// SDK handshake budget; clients are thread-safe and reusable.
fn check_azure_clients_created_per_invocation(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    const AZURE_CLIENT_TYPES: [&str; 8] = [
        "BlobContainerClient",
        "BlobClient",
        "BlobServiceClient",
        "QueueClient",
        "TableClient",
        "ServiceBusClient",
        "CosmosClient",
        "SecretClient",
    ];
    azure_function_methods(root, source)
        .into_iter()
        .filter_map(|method| body_of(method))
        .flat_map(|body| collect_kinds(body, &["object_creation_expression"]))
        .filter(|creation| !is_error_tainted(*creation))
        .filter(|creation| {
            AZURE_CLIENT_TYPES.contains(&simple_name(creation_type_text(*creation, source)))
        })
        .map(|creation| {
            issue(
                language,
                "S6420",
                "Create this client once and reuse it across invocations.",
                range_of(creation),
            )
        })
        .collect()
}

/// csharpsquid:S6798 — Blazor can only reach public methods through JS
/// interop.
fn check_js_invokable_methods_public(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["method_declaration"])
        .into_iter()
        .filter(|method| has_any_attribute(*method, source, &["JSInvokable"]))
        .filter(|method| !has_modifier(&modifiers_of(*method, source), "public"))
        .map(|method| {
            issue(
                language,
                "S6798",
                "Mark this '[JSInvokable]' method public.",
                range_of(name_anchor(method)),
            )
        })
        .collect()
}

/// Attribute names carrying route templates.
const ROUTE_ATTRIBUTE_NAMES: [&str; 6] = [
    "Route",
    "HttpGet",
    "HttpPost",
    "HttpPut",
    "HttpDelete",
    "HttpPatch",
];

/// Route-template string literals of an attribute application's arguments.
fn route_template_literals(args: Option<Node<'_>>) -> Vec<Node<'_>> {
    args.map(string_literals).unwrap_or_default()
}

/// Whether an attribute application carries a route template.
fn is_route_attribute(name: &str) -> bool {
    ROUTE_ATTRIBUTE_NAMES.contains(&name.trim_end_matches("Attribute"))
}

/// HTTP verb attribute names marking ASP.NET actions.
const VERB_ATTRIBUTE_NAMES: [&str; 6] = [
    "HttpGet",
    "HttpPost",
    "HttpPut",
    "HttpDelete",
    "HttpPatch",
    "AcceptVerbs",
];

/// Whether any attribute on the type marks it API-controller-like.
fn is_api_controller_like(type_node: Node<'_>, source: &str) -> bool {
    has_any_attribute(type_node, source, &["ApiController"])
        || type_node
            .child_by_field_name("name")
            .is_some_and(|name| node_text(name, source).ends_with("Controller"))
}

/// Public action candidates declared by a controller-like type.
fn controller_actions<'t>(type_node: Node<'t>, source: &str) -> Vec<Node<'t>> {
    member_declarations_of_kind(type_node, "method_declaration")
        .into_iter()
        .filter(|method| {
            let modifiers = modifiers_of(*method, source);
            has_modifier(&modifiers, "public")
                && !has_modifier(&modifiers, "static")
                && !has_modifier(&modifiers, "override")
        })
        .filter(|method| {
            method
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source) != "Dispose")
        })
        .filter(|method| !has_any_attribute(*method, source, &["NonAction"]))
        .collect()
}

/// csharpsquid:S6930 — backslashes break route templates on every platform
/// but Windows.
fn check_route_templates_use_forward_slashes(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    attribute_applications(root, source)
        .into_iter()
        .filter(|(name, _, _)| is_route_attribute(name))
        .flat_map(|(_, args, _)| route_template_literals(args))
        .filter(|literal| literal_inner_text(*literal, source).contains('\\'))
        .map(|literal| {
            issue(
                language,
                "S6930",
                "Use forward slashes in this route template.",
                range_of(literal),
            )
        })
        .collect()
}

/// csharpsquid:S6931 — action-level route templates starting with '/' escape
/// the controller prefix entirely.
fn check_action_routes_not_rooted(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (name, args, attribute) in attribute_applications(root, source) {
        if !is_route_attribute(name) {
            continue;
        }
        let Some(declaration) = attributed_declaration(attribute) else {
            continue;
        };
        if declaration.kind() != "method_declaration" {
            continue;
        }
        for literal in route_template_literals(args) {
            let template = literal_inner_text(literal, source);
            if template.starts_with('/') && !template.starts_with("~/") {
                issues.push(issue(
                    language,
                    "S6931",
                    "Start this route template without a leading slash.",
                    range_of(attribute),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S6932 — raw request reads bypass binding and validation;
/// model parameters document the contract.
fn check_model_binding_over_raw_request_reads(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    banned_member_accesses(root, source, "Request", &["Form", "Query", "Body"])
        .into_iter()
        .map(|access| {
            issue(
                language,
                "S6932",
                "Bind this data through a model instead of reading the request.",
                range_of(access),
            )
        })
        .collect()
}

/// csharpsquid:S6934 — repeating templates on every action signals a missing
/// controller-level '[Route]'.
fn check_controller_level_route_present(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_node in collect_kinds(root, &["class_declaration"]) {
        if is_error_tainted(class_node) || has_any_attribute(class_node, source, &["Route"]) {
            continue;
        }
        let action_templates = controller_actions(class_node, source).iter().any(|method| {
            attributes_of(*method, source)
                .iter()
                .any(|name| ROUTE_ATTRIBUTE_NAMES.contains(name))
        });
        if action_templates {
            issues.push(issue(
                language,
                "S6934",
                "Declare a controller-level '[Route]' for these action templates.",
                range_of(class_node),
            ));
        }
    }
    issues
}

/// csharpsquid:S6961 — API controllers derive `ControllerBase`, which lacks
/// view support they must never use.
fn check_api_controllers_derive_base(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["class_declaration"])
        .into_iter()
        .filter(|class_node| base_simple_names(*class_node, source).contains(&"Controller"))
        .filter(|class_node| {
            has_any_attribute(*class_node, source, &["ApiController"])
                || controller_actions(*class_node, source)
                    .iter()
                    .any(|action| has_any_attribute(*action, source, &VERB_ATTRIBUTE_NAMES))
        })
        .map(|class_node| {
            issue(
                language,
                "S6961",
                "Derive API controllers from 'ControllerBase'.",
                range_of(class_node),
            )
        })
        .collect()
}

/// csharpsquid:S6962 — hand-rolled `HttpClient` instances rot sockets;
/// `IHttpClientFactory` pools them.
fn check_http_clients_via_factory(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["object_creation_expression"])
        .into_iter()
        .filter(|creation| !is_error_tainted(*creation))
        .filter(|creation| simple_name(creation_type_text(*creation, source)) == "HttpClient")
        .map(|creation| {
            issue(
                language,
                "S6962",
                "Create 'HttpClient' through 'IHttpClientFactory' instead.",
                range_of(creation),
            )
        })
        .collect()
}

/// csharpsquid:S6965 — actions without an HTTP verb annotation answer every
/// verb, including the dangerous ones.
fn check_actions_annotated_with_verbs(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["class_declaration"])
        .into_iter()
        .filter(|class_node| is_api_controller_like(*class_node, source))
        .flat_map(|class_node| controller_actions(class_node, source))
        .filter(|action| !has_any_attribute(*action, source, &VERB_ATTRIBUTE_NAMES))
        .map(|action| {
            issue(
                language,
                "S6965",
                "Annotate this action with an HTTP verb attribute.",
                range_of(name_anchor(action)),
            )
        })
        .collect()
}

/// Simple types a binder handles without a complex model.
fn is_simple_binding_type(type_text: &str) -> bool {
    const SIMPLE_TYPES: [&str; 18] = [
        "bool",
        "byte",
        "sbyte",
        "char",
        "short",
        "ushort",
        "int",
        "uint",
        "long",
        "ulong",
        "float",
        "double",
        "decimal",
        "string",
        "Guid",
        "DateTime",
        "DateTimeOffset",
        "CancellationToken",
    ];
    SIMPLE_TYPES.contains(&type_text.trim_end_matches('?').trim_end_matches("[]"))
}

/// csharpsquid:S6967 — actions receiving models must gate their use behind
/// 'ModelState.IsValid'.
fn check_model_state_checked_for_models(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["class_declaration"])
        .into_iter()
        .filter(|class_node| is_api_controller_like(*class_node, source))
        .flat_map(|class_node| controller_actions(class_node, source))
        .filter(|action| {
            parameters_of(*action).iter().any(|parameter| {
                parameter
                    .child_by_field_name("type")
                    .is_some_and(|ty| !is_simple_binding_type(node_text(ty, source)))
            })
        })
        .filter(|action| {
            body_of(*action)
                .is_none_or(|body| !node_text(body, source).contains("ModelState.IsValid"))
        })
        .map(|action| {
            issue(
                language,
                "S6967",
                "Check 'ModelState.IsValid' before using bound model data.",
                range_of(name_anchor(action)),
            )
        })
        .collect()
}

/// csharpsquid:S6968 — declared success responses keep generated clients
/// honest about what an action returns.
fn check_produces_response_type_annotated(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["method_declaration"])
        .into_iter()
        .filter(|action| has_any_attribute(*action, source, &VERB_ATTRIBUTE_NAMES))
        .filter(|action| return_type_text(*action, source) != "void")
        .filter(|action| !has_any_attribute(*action, source, &["ProducesResponseType"]))
        .map(|action| {
            issue(
                language,
                "S6968",
                "Declare '[ProducesResponseType]' for this action's responses.",
                range_of(name_anchor(action)),
            )
        })
        .collect()
}

/// csharpsquid:S5122 — reflecting any origin erases the same-origin
/// protection CORS exists to provide.
fn check_permissive_cors(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const ANY_ORIGIN_MARKERS: [&str; 1] = ["AllowAnyOrigin"];
    let mut issues: Vec<Issue> = identifier_usages(root, source, &ANY_ORIGIN_MARKERS)
        .into_iter()
        .map(|identifier| {
            issue(
                language,
                "S5122",
                "Restrict CORS responses to trusted origins.",
                range_of(identifier),
            )
        })
        .collect();
    for literal in string_literals(root) {
        if is_error_tainted(literal) {
            continue;
        }
        let lowered = literal_inner_text(literal, source).to_ascii_lowercase();
        if lowered.contains("access-control-allow-origin") && lowered.contains('*') {
            issues.push(issue(
                language,
                "S5122",
                "Restrict CORS responses to trusted origins.",
                range_of(literal),
            ));
        }
    }
    issues
}

/// csharpsquid:S7039 — 'unsafe-inline' or 'unsafe-eval' sources hollow out
/// the Content-Security-Policy.
fn check_permissive_csp(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const UNSAFE_CSP_SOURCES: [&str; 2] = ["unsafe-inline", "unsafe-eval"];
    let mut issues = Vec::new();
    for literal in string_literals(root) {
        if is_error_tainted(literal) {
            continue;
        }
        let lowered = literal_inner_text(literal, source).to_ascii_lowercase();
        let permissive = lowered.contains("content-security-policy")
            && UNSAFE_CSP_SOURCES
                .iter()
                .any(|source_token| lowered.contains(source_token));
        if permissive {
            issues.push(issue(
                language,
                "S7039",
                "Serve a restrictive Content-Security-Policy.",
                range_of(literal),
            ));
        }
    }
    issues
}

/// csharpsquid:S5693 — request bodies beyond the tolerated size exhaust
/// server memory.
fn check_request_size_limits(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    /// Catalog default `fileUploadSizeLimit` for csharpsquid:S5693.
    const REQUEST_BODY_LIMIT_BYTES: u64 = 8_388_608;
    const LIMIT_TARGETS: [&str; 4] = [
        "MaxRequestBodySize",
        "MaxRequestBodyLength",
        "MultipartBodyLengthLimit",
        "FormSize",
    ];
    collect_kinds(root, &["assignment_expression"])
        .into_iter()
        .filter(|assignment| !is_error_tainted(*assignment))
        .filter(|assignment| operator_of(*assignment) == Some("="))
        .filter(|assignment| {
            binary_operands(*assignment).is_some_and(|(target, value)| {
                LIMIT_TARGETS
                    .iter()
                    .any(|limit| node_text(target, source).ends_with(limit))
                    && value.kind() == "integer_literal"
                    && integer_literal_value(node_text(value, source))
                        .is_some_and(|bytes| bytes > REQUEST_BODY_LIMIT_BYTES)
            })
        })
        .map(|assignment| {
            issue(
                language,
                "S5693",
                format!("Keep request bodies at or below {REQUEST_BODY_LIMIT_BYTES} bytes."),
                range_of(assignment),
            )
        })
        .collect()
}

/// Gathers every Tier-A12 security deny/require-list issue.
fn security_deny_list_issues(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_operation_contract_pairing(root, source, language));
    issues.extend(check_one_way_contracts_return_void(root, source, language));
    issues.extend(check_pure_methods_return_values(root, source, language));
    issues.extend(check_winforms_entry_points(root, source, language));
    issues.extend(check_conflicting_transparency_attributes(
        root, source, language,
    ));
    issues.extend(check_serialization_constructors_secured(
        root, source, language,
    ));
    issues.extend(check_optional_fields_have_deserialization_hooks(
        root, source, language,
    ));
    issues.extend(check_serialization_event_handler_shapes(
        root, source, language,
    ));
    issues.extend(check_argument_exception_param_names(root, source, language));
    issues.extend(check_empty_guid_creations(root, source, language));
    issues.extend(check_constructor_argument_names(root, source, language));
    issues.extend(check_part_creation_policy_needs_export(
        root, source, language,
    ));
    issues.extend(check_weak_ssl_protocols(root, source, language));
    issues.extend(check_weak_hash_algorithms(root, source, language));
    issues.extend(check_insecure_cipher_modes(root, source, language));
    issues.extend(check_robust_ciphers_required(root, source, language));
    issues.extend(check_cryptographic_keys_robust(root, source, language));
    issues.extend(check_jwt_strong_algorithms(root, source, language));
    issues.extend(check_clear_text_protocols(root, source, language));
    issues.extend(check_publicly_writable_temp_paths(root, source, language));
    issues.extend(check_predictable_temp_files(root, source, language));
    issues.extend(check_debugging_left_enabled(root, source, language));
    issues.extend(check_request_validation_disabled(root, source, language));
    issues.extend(check_antiforgery_disabled(root, source, language));
    issues.extend(check_unrestricted_deserialization(root, source, language));
    issues.extend(check_unbounded_archive_extraction(root, source, language));
    issues.extend(check_permissive_cors(root, source, language));
    issues.extend(check_permissive_csp(root, source, language));
    issues.extend(check_request_size_limits(root, source, language));
    issues
}

/// Placeholder gathering point for the remaining Tier-A13 date/time and
/// ASP.NET heuristics; populated group by group.
fn datetime_aspnet_issues(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_direct_datetime_usage(root, source, language));
    issues.extend(check_datetime_now_for_timing(root, source, language));
    issues.extend(check_datetime_kind_specified(root, source, language));
    issues.extend(check_unix_epoch_literal(root, source, language));
    issues.extend(check_find_system_time_zone_without_converter(
        root, source, language,
    ));
    issues.extend(check_culture_less_date_parsing(root, source, language));
    issues.extend(check_hardcoded_date_formats(root, source, language));
    issues.extend(check_azure_function_instance_state(root, source, language));
    issues.extend(check_azure_functions_catch_failures(root, source, language));
    issues.extend(check_azure_functions_do_not_block(root, source, language));
    issues.extend(check_azure_catches_log_failures(root, source, language));
    issues.extend(check_azure_clients_created_per_invocation(
        root, source, language,
    ));
    issues.extend(check_js_invokable_methods_public(root, source, language));
    issues.extend(check_route_templates_use_forward_slashes(
        root, source, language,
    ));
    issues.extend(check_action_routes_not_rooted(root, source, language));
    issues.extend(check_model_binding_over_raw_request_reads(
        root, source, language,
    ));
    issues.extend(check_controller_level_route_present(root, source, language));
    issues.extend(check_api_controllers_derive_base(root, source, language));
    issues.extend(check_http_clients_via_factory(root, source, language));
    issues.extend(check_actions_annotated_with_verbs(root, source, language));
    issues.extend(check_model_state_checked_for_models(root, source, language));
    issues.extend(check_produces_response_type_annotated(
        root, source, language,
    ));
    issues
}
// ---------------------------------------------------------------------------
// A14 — logging family (templates, placeholders, loggers)
// ---------------------------------------------------------------------------

/// `Microsoft.Extensions.Logging`-style structured-logging entry points
/// (`ILogger.Log*`, Serilog-style `Log.*`).
const LOG_METHOD_NAMES: [&str; 7] = [
    "Log",
    "LogTrace",
    "LogDebug",
    "LogInformation",
    "LogWarning",
    "LogError",
    "LogCritical",
];

/// csharpsquid:S6664 severity buckets with their tolerated call counts per
/// method body (debug=4, information=2, warning=1, error=1).
const LOG_LEVEL_LIMITS: [(&str, u32); 4] = [
    ("debug", 4),
    ("information", 2),
    ("warning", 1),
    ("error", 1),
];

/// `TraceSwitch` level properties that should not gate conditional traces.
const TRACE_SWITCH_LEVELS: [&str; 4] = ["TraceError", "TraceWarning", "TraceInfo", "TraceVerbose"];

/// Severity bucket of a logging entry point (`LogDebug` → debug).
fn log_level_of(callee: &str) -> Option<&'static str> {
    match callee {
        "LogTrace" | "LogDebug" => Some("debug"),
        "LogInformation" | "Log" => Some("information"),
        "LogWarning" => Some("warning"),
        "LogError" | "LogCritical" => Some("error"),
        _ => None,
    }
}

/// Tolerated number of `{level}` log calls inside one method body.
fn log_level_limit(level: &str) -> u32 {
    for (name, limit) in LOG_LEVEL_LIMITS {
        if name == level {
            return limit;
        }
    }
    0
}

/// Whether an invocation looks like structured logging through a logger
/// member (`logger.LogError(...)`, `Log.Information(...)`).
fn is_logging_call(invocation: Node<'_>, source: &str) -> bool {
    callee_name(invocation, source).is_some_and(|name| {
        LOG_METHOD_NAMES.contains(&name) && invocation_receiver(invocation).is_some()
    })
}

/// Logging invocations inside `scope`, in document order.
fn logging_calls<'t>(scope: Node<'t>, source: &str) -> Vec<Node<'t>> {
    collect_kinds(scope, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call) && is_logging_call(*call, source))
        .collect()
}

/// A call's first plain string-literal argument, paired with the unquoted
/// inner text. Interpolated templates yield nothing here.
fn template_argument<'a>(call: Node<'a>, source: &'a str) -> Option<(Node<'a>, &'a str)> {
    let first = invocation_arguments(call).into_iter().next()?;
    let expression = argument_expression(first);
    let literal = (expression.kind() == "string_literal").then_some(expression)?;
    Some((literal, literal_inner_text(literal, source)))
}

/// Placeholder names inside a message template, in textual order.
fn template_placeholders(template: &str) -> Vec<&str> {
    let mut names = Vec::new();
    let bytes = template.as_bytes();
    let mut index = 0;
    while let Some(offset) = bytes[index..].iter().position(|byte| *byte == b'{') {
        let open = index + offset + 1;
        match bytes[open..].iter().position(|byte| *byte == b'}') {
            Some(close) if close > 0 && !bytes[open..open + close].contains(&b'{') => {
                names.push(&template[open..open + close]);
                index = open + close + 1;
            }
            _ => break,
        }
    }
    names
}

/// Whether a message template parses: balanced braces, no empty or nested
/// placeholders, and no stray closing brace.
fn template_is_valid(template: &str) -> bool {
    let bytes = template.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'{' => {
                let Some(close) = bytes[index + 1..]
                    .iter()
                    .position(|byte| *byte == b'}')
                    .map(|relative| index + 1 + relative)
                else {
                    return false;
                };
                if close == index + 1 || bytes[index + 1..close].contains(&b'{') {
                    return false;
                }
                index = close + 1;
            }
            b'}' => return false,
            _ => index += 1,
        }
    }
    true
}

/// csharpsquid:S6670 — `Trace` output bypasses sinks, levels, correlation.
fn check_trace_writes(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    banned_member_accesses(root, source, "Trace", &["Write", "WriteLine"])
        .into_iter()
        .map(|access| {
            issue(
                language,
                "S6670",
                "Replace this 'Trace' output with proper logging.",
                range_of(access),
            )
        })
        .collect()
}

/// csharpsquid:S6675 — gating `WriteLineIf` with a `TraceSwitch` level hides
/// the decision from the configuration system.
fn check_trace_write_line_if_switches(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| invocation_targets(*call, source, Some("Trace"), &["WriteLineIf"]))
        .filter(|call| {
            invocation_arguments(*call).first().is_some_and(|argument| {
                let expression = argument_expression(*argument);
                TRACE_SWITCH_LEVELS.contains(&expression_name(expression, source).unwrap_or(""))
            })
        })
        .map(|call| {
            issue(
                language,
                "S6675",
                "Do not use a 'TraceSwitch' level to gate this trace.",
                range_of(call),
            )
        })
        .collect()
}

/// csharpsquid:S6664 — chatty methods bury signals; each severity bucket has
/// its own tolerated call count per method body.
fn check_log_call_counts(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) {
            continue;
        }
        let Some(body) = body_of(method) else {
            continue;
        };
        let mut counts: std::collections::BTreeMap<&str, u32> = std::collections::BTreeMap::new();
        for call in logging_calls(body, source) {
            if let Some(level) = callee_name(call, source).and_then(log_level_of) {
                *counts.entry(level).or_insert(0) += 1;
            }
        }
        for (level, count) in counts {
            let limit = log_level_limit(level);
            if count > limit {
                issues.push(issue(
                    language,
                    "S6664",
                    format!("Limit {level}-level logging in this method to {limit} calls."),
                    range_of(method),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S6673 — when placeholder and argument names prove a
/// transposition, the placeholders must follow the argument order.
fn check_log_placeholder_order(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in logging_calls(root, source) {
        let Some((literal, template)) = template_argument(call, source) else {
            continue;
        };
        let placeholders = template_placeholders(template);
        let arguments: Vec<Option<&str>> = invocation_arguments(call)
            .iter()
            .skip(1)
            .map(|argument| {
                let expression = argument_expression(*argument);
                (expression.kind() == "identifier").then(|| node_text(expression, source))
            })
            .collect();
        let pairs = placeholders.len().min(arguments.len());
        for index in 0..pairs {
            let Some(expected) = arguments[index] else {
                break;
            };
            if placeholders[index].eq_ignore_ascii_case(expected) {
                continue;
            }
            let swapped = ((index + 1)..pairs).any(|later| {
                arguments[later].is_some_and(|value| {
                    placeholders[index].eq_ignore_ascii_case(value)
                        && placeholders[later].eq_ignore_ascii_case(expected)
                })
            });
            if swapped {
                issues.push(issue(
                    language,
                    "S6673",
                    "Align message-template placeholders with the argument order.",
                    range_of(literal),
                ));
            }
            break;
        }
    }
    issues
}

/// csharpsquid:S6674 — malformed message templates fail at logging time.
fn check_log_template_syntax(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in logging_calls(root, source) {
        let Some((literal, template)) = template_argument(call, source) else {
            continue;
        };
        if !template_is_valid(template) {
            issues.push(issue(
                language,
                "S6674",
                "Fix this malformed message template.",
                range_of(literal),
            ));
        }
    }
    issues
}

fn check_log_unique_placeholders(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in logging_calls(root, source) {
        let Some((literal, template)) = template_argument(call, source) else {
            continue;
        };
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for name in template_placeholders(template) {
            if !seen.insert(name.to_ascii_lowercase()) {
                let shown = format!("{{{name}}}");
                issues.push(issue(
                    language,
                    "S6677",
                    format!("Rename the duplicate placeholder {shown}."),
                    range_of(literal),
                ));
            }
        }
    }
    issues
}
/// csharpsquid:S6678 — placeholders read as property names and must be
/// `PascalCase`; positional numeric slots are exempt.
fn check_log_placeholder_casing(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in logging_calls(root, source) {
        let Some((literal, template)) = template_argument(call, source) else {
            continue;
        };
        for name in template_placeholders(template) {
            let positional = name.chars().all(|character| character.is_ascii_digit());
            if positional || is_pascal_case(name) {
                continue;
            }
            let shown = format!("{{{name}}}");
            issues.push(issue(
                language,
                "S6678",
                format!("Rename the placeholder {shown} to PascalCase."),
                range_of(literal),
            ));
        }
    }
    issues
}

/// csharpsquid:S6667 — catch-block logging that drops the exception loses
/// the stack trace.
fn check_catch_logging_passes_exception(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for clause in collect_kinds(root, &["catch_clause"]) {
        if is_error_tainted(clause) {
            continue;
        }
        let Some(caught) = caught_exception_name(clause, source) else {
            continue;
        };
        let Some(body) = clause.child_by_field_name("body") else {
            continue;
        };
        for call in logging_calls(body, source) {
            let passes = invocation_arguments(call)
                .iter()
                .any(|argument| node_text(*argument, source).contains(caught));
            if !passes {
                issues.push(issue(
                    language,
                    "S6667",
                    "Pass the caught exception to this log call.",
                    range_of(call),
                ));
            }
        }
    }
    issues
}

/// The declared variable name of a catch clause (`catch (Exception ex)`).
fn caught_exception_name<'a>(clause: Node<'_>, source: &'a str) -> Option<&'a str> {
    let mut cursor = clause.walk();
    clause
        .children(&mut cursor)
        .find(|child| child.kind() == "catch_declaration")
        .and_then(|declaration| declaration.child_by_field_name("name"))
        .map(|name| node_text(name, source))
}

/// csharpsquid:S2629 — interpolated or computed templates defeat structured
/// logging; only constant templates can be parsed by log backends.
fn check_constant_log_templates(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    logging_calls(root, source)
        .into_iter()
        .filter_map(|call| {
            invocation_arguments(call)
                .first()
                .copied()
                .map(|first| (call, argument_expression(first)))
        })
        .filter(|(_, expression)| expression.kind() != "string_literal")
        .map(|(call, _)| {
            issue(
                language,
                "S2629",
                "Use a constant message template for this log call.",
                range_of(call),
            )
        })
        .collect()
}

/// csharpsquid:S1312 — logger fields follow one shape so tooling finds them.
fn check_logger_field_modifiers(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for field in collect_kinds(root, &["field_declaration"]) {
        if is_error_tainted(field) {
            continue;
        }
        let logger_named = field_declarator_names(field, source)
            .into_iter()
            .any(|name| matches_logger_format(name, &options.logger_name_format));
        if !logger_named {
            continue;
        }
        let modifiers = modifiers_of(field, source);
        let shaped = ["private", "static", "readonly"]
            .iter()
            .all(|wanted| has_modifier(&modifiers, wanted));
        if !shaped {
            issues.push(issue(
                language,
                "S1312",
                "Declare this logger field 'private static readonly'.",
                range_of(field),
            ));
        }
    }
    issues
}

/// Declarator names of a field or event declaration.
fn field_declarator_names<'a>(field: Node<'_>, source: &'a str) -> Vec<&'a str> {
    collect_kinds(field, &["variable_declarator"])
        .into_iter()
        .filter_map(|declarator| declarator.child_by_field_name("name"))
        .map(|name| node_text(name, source))
        .collect()
}

/// csharpsquid:S3416 — `CreateLogger<T>` must name the enclosing type.
fn check_create_logger_types(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(call) {
            continue;
        }
        let Some(target) = create_logger_target(call, source) else {
            continue;
        };
        let Some(enclosing) = enclosing_type(call) else {
            continue;
        };
        let Some(name) = enclosing.child_by_field_name("name") else {
            continue;
        };
        if simple_name(&target) != node_text(name, source) {
            issues.push(issue(
                language,
                "S3416",
                "Name this logger after its enclosing type.",
                range_of(call),
            ));
        }
    }
    issues
}

/// The type named by `CreateLogger<T>()` or `CreateLogger(typeof(T))`.
fn create_logger_target(call: Node<'_>, source: &str) -> Option<String> {
    let function = invocation_function(call)?;
    let target_node = if function.kind() == "member_access_expression" {
        let mut cursor = function.walk();
        let generic = function
            .children(&mut cursor)
            .find(|child| child.kind() == "generic_name")
            .filter(|generic| {
                first_named_child(*generic)
                    .is_some_and(|identifier| node_text(identifier, source) == "CreateLogger")
            })?;
        let mut generic_cursor = generic.walk();
        generic
            .children(&mut generic_cursor)
            .find(|child| child.kind() == "type_argument_list")?
    } else {
        if callee_name(call, source) != Some("CreateLogger") {
            return None;
        }
        let argument = invocation_arguments(call).into_iter().next()?;
        let expression = argument_expression(argument);
        (expression.kind() == "typeof_expression").then_some(expression)?
    };
    let mut target_cursor = target_node.walk();
    target_node
        .children(&mut target_cursor)
        .find(tree_sitter::Node::is_named)
        .map(|type_node| node_text(type_node, source).to_string())
}

/// csharpsquid:S6672 — an `ILogger<T>` belongs to the type that logs.
fn check_ilogger_generics(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if is_error_tainted(type_node) {
            continue;
        }
        let Some(name) = type_node.child_by_field_name("name") else {
            continue;
        };
        let type_name = node_text(name, source);
        for declaration in collect_kinds(type_node, &["variable_declaration"]) {
            if enclosing_type(declaration).is_none_or(|owner| owner.id() != type_node.id()) {
                continue;
            }
            let Some(type_child) = first_named_child(declaration) else {
                continue;
            };
            let Some(inner) = node_text(type_child, source)
                .strip_prefix("ILogger<")
                .and_then(|rest| rest.strip_suffix('>'))
            else {
                continue;
            };
            if simple_name(inner) != type_name {
                issues.push(issue(
                    language,
                    "S6672",
                    format!("Use 'ILogger<{type_name}>' for loggers of this type."),
                    range_of(declaration),
                ));
            }
        }
    }
    issues
}

/// Gathers every Tier-A14 logging-family issue.
fn logging_issues(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_trace_writes(root, source, language));
    issues.extend(check_trace_write_line_if_switches(root, source, language));
    issues.extend(check_log_call_counts(root, source, language));
    issues.extend(check_log_placeholder_order(root, source, language));
    issues.extend(check_log_template_syntax(root, source, language));
    issues.extend(check_log_unique_placeholders(root, source, language));
    issues.extend(check_log_placeholder_casing(root, source, language));
    issues.extend(check_catch_logging_passes_exception(root, source, language));
    issues.extend(check_constant_log_templates(root, source, language));
    issues.extend(check_logger_field_modifiers(
        root, source, language, options,
    ));
    issues.extend(check_create_logger_types(root, source, language));
    issues.extend(check_ilogger_generics(root, source, language));
    issues
}

// ---------------------------------------------------------------------------
// A15 — LINQ/format/assertion patterns & misc API heuristics
// ---------------------------------------------------------------------------

/// csharpsquid:S1155 — emptiness is what `Any()` expresses.
fn check_any_instead_of_count(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(expression) {
            continue;
        }
        let Some(operator) = operator_of(expression) else {
            continue;
        };
        if operator != "==" && operator != "<=" {
            continue;
        }
        let Some((left, right)) = binary_operands(expression) else {
            continue;
        };
        let zero = |operand: Node<'_>| {
            operand.kind() == "integer_literal" && node_text(operand, source) == "0"
        };
        if (is_count_expression(left, source) && zero(right))
            || (zero(left) && is_count_expression(right, source))
        {
            issues.push(issue(
                language,
                "S1155",
                "Use 'Any()' instead of comparing a count with zero.",
                range_of(expression),
            ));
        }
    }
    issues
}

/// Whether the operand reads a collection size (`.Count()` / `.Count`).
fn is_count_expression(operand: Node<'_>, source: &str) -> bool {
    match operand.kind() {
        "invocation_expression" => callee_name(operand, source) == Some("Count"),
        "member_access_expression" => expression_name(operand, source) == Some("Count"),
        _ => false,
    }
}

/// Whether an invocation feeds a composite format template (`string.Format`,
/// `AppendFormat`, `Console.Write(Line)`).
fn is_composite_format_call(invocation: Node<'_>, source: &str) -> bool {
    invocation_targets(invocation, source, Some("string"), &["Format"])
        || invocation_targets(invocation, source, Some("String"), &["Format"])
        || callee_name(invocation, source) == Some("AppendFormat")
        || invocation_targets(invocation, source, Some("Console"), &["Write", "WriteLine"])
}

/// The composite-format template of a call with the number of arguments
/// following it; tolerates a leading `IFormatProvider` argument.
fn composite_template<'a>(call: Node<'a>, source: &'a str) -> Option<(Node<'a>, &'a str, usize)> {
    let arguments = invocation_arguments(call);
    let position = arguments
        .iter()
        .position(|argument| argument_expression(*argument).kind() == "string_literal")?;
    let literal = argument_expression(arguments[position]);
    let budget = arguments.len() - position - 1;
    Some((literal, literal_inner_text(literal, source), budget))
}

/// Numeric index of a `{12}`-style format slot.
fn format_slot_index(name: &str) -> Option<u32> {
    if !name.chars().all(|character| character.is_ascii_digit()) {
        return None;
    }
    name.parse().ok()
}

/// csharpsquid:S2275 — every referenced format slot needs an argument.
fn check_format_argument_counts(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(call) || !is_composite_format_call(call, source) {
            continue;
        }
        let Some((literal, template, budget)) = composite_template(call, source) else {
            continue;
        };
        let highest = template_placeholders(template)
            .iter()
            .filter_map(|name| format_slot_index(name))
            .max();
        if highest.is_some_and(|index| index + 1 > to_u32(budget)) {
            issues.push(issue(
                language,
                "S2275",
                "Match the format-string slots to the arguments of this call.",
                range_of(literal),
            ));
        }
    }
    issues
}

/// Composite-format brace scan honoring doubled-brace escapes.
fn composite_template_is_valid(template: &str) -> bool {
    let bytes = template.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'{' => {
                if bytes.get(index + 1) == Some(&b'{') {
                    index += 2;
                    continue;
                }
                let Some(close) = bytes[index + 1..]
                    .iter()
                    .position(|byte| *byte == b'}')
                    .map(|relative| index + 1 + relative)
                else {
                    return false;
                };
                if close == index + 1 || bytes[index + 1..close].contains(&b'{') {
                    return false;
                }
                index = close + 1;
            }
            b'}' => {
                if bytes.get(index + 1) != Some(&b'}') {
                    return false;
                }
                index += 2;
            }
            _ => index += 1,
        }
    }
    true
}

/// csharpsquid:S3457 — composite formats need valid slots, and pointless
/// format strings hide plain output.
fn check_composite_format_usage(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(call) || !is_composite_format_call(call, source) {
            continue;
        }
        let Some((literal, template, budget)) = composite_template(call, source) else {
            continue;
        };
        if !composite_template_is_valid(template) {
            issues.push(issue(
                language,
                "S3457",
                "Fix this malformed composite format string.",
                range_of(literal),
            ));
        } else if !template.contains('{') && budget > 0 {
            issues.push(issue(
                language,
                "S3457",
                "Pass the arguments directly instead of using this format string.",
                range_of(literal),
            ));
        }
    }
    issues
}

/// Flattens an `||` chain into its operands.
fn or_chain_operands(expression: Node<'_>) -> Vec<Node<'_>> {
    if operator_of(expression) == Some("||")
        && let Some((left, right)) = binary_operands(expression)
    {
        let mut operands = or_chain_operands(left);
        operands.extend(or_chain_operands(right));
        return operands;
    }
    vec![expression]
}

/// csharpsquid:S3937 — three-or-more equality literals over one identifier
/// should step regularly.
fn check_regular_number_patterns(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(expression) || operator_of(expression) != Some("||") {
            continue;
        }
        if expression.parent().is_some_and(|parent| {
            parent.kind() == "binary_expression" && operator_of(parent) == Some("||")
        }) {
            continue;
        }
        let operands = or_chain_operands(expression);
        let mut subject: Option<&str> = None;
        let mut values: Vec<i128> = Vec::new();
        let mut leaves: Vec<Node<'_>> = Vec::new();
        let mut regular_shape = true;
        for operand in &operands {
            let equality = operator_of(*operand) == Some("==")
                && binary_operands(*operand).is_some_and(|(left, right)| {
                    left.kind() == "identifier"
                        && right.kind() == "integer_literal"
                        && integer_literal_value(node_text(right, source)).is_some()
                        && {
                            let name = node_text(left, source);
                            match subject {
                                None => {
                                    subject = Some(name);
                                    true
                                }
                                Some(seen) => seen == name,
                            }
                        }
                });
            if !equality {
                regular_shape = false;
                break;
            }
            let (_, right) = binary_operands(*operand).unwrap_or((*operand, *operand));
            values.push(i128::from(
                integer_literal_value(node_text(right, source)).unwrap_or(0),
            ));
            leaves.push(*operand);
        }
        if !regular_shape || leaves.len() < 3 {
            continue;
        }
        let uniform = values
            .windows(2)
            .all(|pair| pair[1] - pair[0] == values[1] - values[0]);
        if !uniform {
            issues.push(issue(
                language,
                "S3937",
                "Make this sequence of compared numbers regular.",
                range_of(leaves[0]),
            ));
        }
    }
    issues
}

/// The element-access target of an assignment statement (`arr[i] = v`),
/// keyed by its full target text.
fn element_write_target<'a>(statement: Node<'_>, source: &'a str) -> Option<&'a str> {
    let inner = first_named_child(statement)?;
    if inner.kind() != "assignment_expression" || child_operator(inner, source) != Some("=") {
        return None;
    }
    let (target, _) = binary_operands(inner)?;
    (target.kind() == "element_access_expression").then(|| node_text(target, source))
}

/// The operator token behind a `left/right` expression's dedicated field.
fn child_operator<'a>(expression: Node<'_>, source: &'a str) -> Option<&'a str> {
    expression
        .child_by_field_name("operator")
        .map(|operator| node_text(operator, source))
}

/// csharpsquid:S4143 — consecutive writes to the same element leave the
/// first one dead.
fn check_double_element_writes(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for block in collect_kinds(root, &["block"]) {
        let statements = block_statements(block);
        for pair in statements.windows(2) {
            let (Some(first), Some(second)) = (
                element_write_target(pair[0], source),
                element_write_target(pair[1], source),
            ) else {
                continue;
            };
            if first == second {
                issues.push(issue(
                    language,
                    "S4143",
                    "Remove this write; it is overwritten by the next statement.",
                    range_of(pair[0]),
                ));
            }
        }
    }
    issues
}

/// Methods grouped by declared name within each type.
fn methods_grouped_by_name<'t>(
    root: Node<'t>,
    source: &str,
) -> std::collections::BTreeMap<(usize, String), Vec<Node<'t>>> {
    let mut groups: std::collections::BTreeMap<(usize, String), Vec<Node<'t>>> =
        std::collections::BTreeMap::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) {
            continue;
        }
        let owner = enclosing_type(method).map_or(0, |owner| owner.id());
        let name = method
            .child_by_field_name("name")
            .map(|name| node_text(name, source).to_string())
            .unwrap_or_default();
        groups.entry((owner, name)).or_default().push(method);
    }
    groups
}

/// csharpsquid:S3994 — string parameters duplicating a sibling `System.Uri`
/// overload push conversion work onto callers.
fn check_uri_string_parameters(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for methods in methods_grouped_by_name(root, source).into_values() {
        if methods.len() < 2 {
            continue;
        }
        let shapes: Vec<Vec<String>> = methods
            .iter()
            .map(|method| {
                parameters_of(*method)
                    .iter()
                    .filter_map(|parameter| parameter.child_by_field_name("type"))
                    .map(|type_node| simple_name(node_text(type_node, source)).to_string())
                    .collect()
            })
            .collect();
        for index in 0..shapes.iter().map(Vec::len).max().unwrap_or(0) {
            let has_uri = shapes
                .iter()
                .any(|shape| shape.get(index).is_some_and(|name| name == "Uri"));
            if !has_uri {
                continue;
            }
            for (method, shape) in methods.iter().zip(&shapes) {
                if shape.get(index).is_some_and(|name| name == "string") {
                    issues.push(issue(
                        language,
                        "S3994",
                        "Accept a 'System.Uri' instead of a string here.",
                        range_of(*method),
                    ));
                }
            }
        }
    }
    issues
}

/// csharpsquid:S3995 — string returns beside a sibling `System.Uri`
/// overload lose structure.
fn check_uri_string_returns(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for methods in methods_grouped_by_name(root, source).into_values() {
        if methods.len() < 2 {
            continue;
        }
        let returns_uri = methods
            .iter()
            .any(|method| simple_name(return_type_text(*method, source)) == "Uri");
        if !returns_uri {
            continue;
        }
        for method in &methods {
            if simple_name(return_type_text(*method, source)) == "string" {
                issues.push(issue(
                    language,
                    "S3995",
                    "Return a 'System.Uri' instead of a string here.",
                    range_of(name_anchor(*method)),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S3996 — URI-named properties should carry real URIs.
fn check_uri_string_properties(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for property in collect_kinds(root, &["property_declaration"]) {
        if is_error_tainted(property) {
            continue;
        }
        let named_uri = property
            .child_by_field_name("name")
            .and_then(|name| node_text(name, source).strip_suffix("Uri"))
            .is_some_and(|prefix| !prefix.is_empty());
        let typed_string = property
            .child_by_field_name("type")
            .is_some_and(|type_node| simple_name(node_text(type_node, source)) == "string");
        if named_uri && typed_string {
            issues.push(issue(
                language,
                "S3996",
                "Expose this URI-valued property as 'System.Uri'.",
                range_of(property),
            ));
        }
    }
    issues
}

/// Client members whose well-known string overloads have `System.Uri`
/// siblings.
const STRING_URI_OVERLOAD_METHODS: [&str; 5] = [
    "DownloadString",
    "UploadString",
    "DownloadData",
    "OpenRead",
    "OpenWrite",
];

/// csharpsquid:S4005 — pass parsed `System.Uri` values instead of raw
/// strings at dual-overload call sites.
fn check_string_arguments_at_uri_overloads(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(call) {
            continue;
        }
        let targets = callee_name(call, source)
            .is_some_and(|name| STRING_URI_OVERLOAD_METHODS.contains(&name));
        if !targets {
            continue;
        }
        let Some(first) = invocation_arguments(call).first().copied() else {
            continue;
        };
        if argument_expression(first).kind() == "string_literal" {
            issues.push(issue(
                language,
                "S4005",
                "Create a 'System.Uri' and pass it to this call.",
                range_of(call),
            ));
        }
    }
    issues
}

/// csharpsquid:S3257 — when the initializer spells out the type again, `var`
/// keeps the declaration honest without repeating it.
fn check_concise_declarations(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for statement in collect_kinds(root, &["local_declaration_statement"]) {
        if is_error_tainted(statement) || modifiers_of(statement, source).contains(&"const") {
            continue;
        }
        let Some(declaration) = first_named_child(statement) else {
            continue;
        };
        let Some(type_node) = declaration.child_by_field_name("type") else {
            continue;
        };
        if type_node.kind() == "implicit_type" {
            continue;
        }
        let declared = node_text(type_node, source)
            .split_whitespace()
            .collect::<String>();
        for declarator in collect_kinds(declaration, &["variable_declarator"]) {
            let Some(name) = declarator.child_by_field_name("name") else {
                continue;
            };
            let Some(initializer) = declarator_initializer(declarator, name) else {
                continue;
            };
            if initializer.kind() != "object_creation_expression" {
                continue;
            }
            let created = creation_type_text(initializer, source)
                .split_whitespace()
                .collect::<String>();
            if created == declared {
                issues.push(issue(
                    language,
                    "S3257",
                    "Use 'var' for this declaration.",
                    range_of(declarator),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S3244 — a fresh anonymous delegate never equals the one that
/// subscribed, so the handler stays attached.
fn check_anonymous_unsubscriptions(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["assignment_expression"])
        .into_iter()
        .filter(|assignment| !is_error_tainted(*assignment))
        .filter(|assignment| child_operator(*assignment, source) == Some("-="))
        .filter(|assignment| {
            binary_operands(*assignment).is_some_and(|(_, value)| {
                matches!(
                    value.kind(),
                    "lambda_expression" | "anonymous_method_expression"
                )
            })
        })
        .map(|assignment| {
            issue(
                language,
                "S3244",
                "Unsubscribe with the original delegate, not a new anonymous one.",
                range_of(assignment),
            )
        })
        .collect()
}

/// csharpsquid:S3247 — repeated casts of one expression invite drift; cast
/// once and reuse the result.
fn check_duplicate_casts(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut seen: std::collections::BTreeMap<(usize, String, String), u32> =
        std::collections::BTreeMap::new();
    let mut issues = Vec::new();
    for cast in collect_kinds(root, &["cast_expression"]) {
        if is_error_tainted(cast) {
            continue;
        }
        let Some((target_type, operand)) = cast_fields(cast, source) else {
            continue;
        };
        let scope = enclosing_method(cast).map_or(0, |method| method.id());
        let key = (scope, target_type, operand);
        let count = seen.entry(key).or_insert(0);
        *count += 1;
        if *count > 1 {
            issues.push(issue(
                language,
                "S3247",
                "Cast this expression once and store the result.",
                range_of(cast),
            ));
        }
    }
    issues
}

/// Cast type and trimmed operand text of a `(T) x` expression.
fn cast_fields(cast: Node<'_>, source: &str) -> Option<(String, String)> {
    let target_type = cast
        .child_by_field_name("type")
        .map(|type_node| node_text(type_node, source).to_string())?;
    let operand = cast
        .child_by_field_name("value")
        .map(|value| node_text(value, source).trim().to_string())?;
    Some((target_type, operand))
}

/// csharpsquid:S1185 — overrides that only forward to `base` add noise.
fn check_trivial_base_forwarding_overrides(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) || !has_modifier(&modifiers_of(method, source), "override") {
            continue;
        }
        let Some(body) = body_of(method) else {
            continue;
        };
        let statements = block_statements(body);
        if statements.len() != 1 {
            continue;
        }
        let Some(name) = method.child_by_field_name("name") else {
            continue;
        };
        let forwards = forwards_to_base(statements[0], node_text(name, source), source);
        if forwards {
            issues.push(issue(
                language,
                "S1185",
                "Remove this override; it only forwards to the base member.",
                range_of(name_anchor(method)),
            ));
        }
    }
    issues
}

/// Whether the single statement is a bare or returning `base.M(...)` call.
fn forwards_to_base(statement: Node<'_>, member: &str, source: &str) -> bool {
    let Some(inner) = first_named_child(statement) else {
        return false;
    };
    let invocation = match inner.kind() {
        "return_statement" => first_named_child(inner),
        "invocation_expression" => Some(inner),
        _ => None,
    };
    let Some(invocation) = invocation else {
        return false;
    };
    callee_name(invocation, source) == Some(member)
        && invocation_function(invocation).is_some_and(|function| {
            function.kind() == "member_access_expression"
                && first_child_token_text(function, source) == "base"
        })
}

/// The leading token of a node (`base` of a `base.M` member access).
fn first_child_token_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .next()
        .map_or("", |first| node_text(first, source))
}

/// csharpsquid:S3237 — setters exist to consume `value`.
fn check_setters_assign_value(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for accessor in collect_kinds(root, &["accessor_declaration"]) {
        if accessor_keyword(accessor, source) != "set" {
            continue;
        }
        let Some(body) = accessor.child_by_field_name("body") else {
            continue;
        };
        let ignores_value =
            collect_kinds(body, &["assignment_expression"])
                .iter()
                .any(|assignment| {
                    child_operator(*assignment, source) == Some("=")
                        && binary_operands(*assignment).is_some_and(|(target, value)| {
                            target.kind() == "identifier"
                                && node_text(target, source) != "value"
                                && value.kind() == "identifier"
                                && node_text(value, source) != "value"
                                && node_text(value, source) != node_text(target, source)
                        })
                });
        if ignores_value {
            issues.push(issue(
                language,
                "S3237",
                "Assign the 'value' keyword in this setter.",
                range_of(accessor),
            ));
        }
    }
    issues
}

/// csharpsquid:S4049 — `Get`/`Set` pairs read as properties.
fn check_accessor_shaped_methods(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) {
            continue;
        }
        let Some(name) = method.child_by_field_name("name") else {
            continue;
        };
        let spelled = node_text(name, source);
        let returns_void = simple_name(return_type_text(method, source)) == "void";
        let parameters = parameters_of(method).len();
        if spelled.len() > 3
            && spelled.starts_with('G')
            && spelled[1..].starts_with("et")
            && spelled
                .chars()
                .nth(3)
                .is_some_and(|c: char| c.is_ascii_uppercase())
            && parameters == 0
            && !returns_void
        {
            issues.push(issue(
                language,
                "S4049",
                "Convert this getter method into a property.",
                range_of(name_anchor(method)),
            ));
        } else if spelled.len() > 3
            && spelled.starts_with("Set")
            && spelled
                .chars()
                .nth(3)
                .is_some_and(|c: char| c.is_ascii_uppercase())
            && parameters == 1
        {
            issues.push(issue(
                language,
                "S4049",
                "Convert this setter method into a property.",
                range_of(name_anchor(method)),
            ));
        }
    }
    issues
}

/// Gathers the Tier-A15 LINQ/format/API-heuristic slice.
fn linq_api_issues(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_any_instead_of_count(root, source, language));
    issues.extend(check_format_argument_counts(root, source, language));
    issues.extend(check_composite_format_usage(root, source, language));
    issues.extend(check_regular_number_patterns(root, source, language));
    issues.extend(check_double_element_writes(root, source, language));
    issues.extend(check_uri_string_parameters(root, source, language));
    issues.extend(check_uri_string_returns(root, source, language));
    issues.extend(check_uri_string_properties(root, source, language));
    issues.extend(check_string_arguments_at_uri_overloads(
        root, source, language,
    ));
    issues.extend(check_concise_declarations(root, source, language));
    issues.extend(check_anonymous_unsubscriptions(root, source, language));
    issues.extend(check_duplicate_casts(root, source, language));
    issues.extend(check_trivial_base_forwarding_overrides(
        root, source, language,
    ));
    issues.extend(check_setters_assign_value(root, source, language));
    issues.extend(check_accessor_shaped_methods(root, source, language));
    issues.extend(check_lowercase_normalization(root, source, language));
    issues.extend(check_culture_less_conversions(root, source, language));
    issues.extend(check_culture_less_comparisons(root, source, language));
    issues.extend(check_culture_less_searches(root, source, language));
    issues.extend(check_hardcoded_connection_passwords(root, source, language));
    issues.extend(check_weak_identity_locks(root, language));
    issues.extend(check_locks_on_locals(root, source, language));
    issues.extend(check_locks_on_mutable_fields(root, source, language));
    issues.extend(check_datetime_key_members(root, source, language));
    issues.extend(check_outdated_base_types(root, source, language));
    issues.extend(check_tests_include_assertions(root, source, language));
    issues.extend(check_literal_assertions(root, source, language));
    issues.extend(check_unconstrained_assertions(root, source, language));
    issues.extend(check_reversed_assertion_arguments(root, source, language));
    issues.extend(check_test_classes_contain_tests(root, source, language));
    issues.extend(check_task_returns_null(root, source, language));
    issues.extend(check_dispose_pattern(root, source, language));
    issues.extend(check_dispose_needs_interface(root, source, language));
    issues.extend(check_utility_class_constructors(root, source, language));
    issues.extend(check_reserved_exception_throws(root, source, language));
    issues.extend(check_throws_in_finally(root, language));
    issues.extend(check_null_reference_catches(root, source, language));
    issues.extend(check_double_reported_catches(root, source, language));
    issues.extend(check_general_exception_catches(root, source, language));
    issues.extend(check_unchecked_sums(root, source, language));
    issues.extend(check_strings_matching_parameters(root, source, language));
    issues.extend(check_mergeable_try_statements(root, source, language));
    issues.extend(check_redundant_modifiers(root, source, language));
    let (fixmes, todos) = comment_tag_issues(root, source, language);
    issues.extend(fixmes);
    issues.extend(todos);
    issues.extend(check_test_method_signatures(root, source, language));
    issues.extend(check_ignored_generic_exceptions(root, source, language));
    issues.extend(check_rethrow_only_catches(root, language));
    issues.extend(check_transposed_operators(source, language));
    issues.extend(check_foreach_iteration_casts(root, source, language));
    issues.extend(check_pure_debug_assertions(root, source, language));
    issues.extend(check_overlapping_optional_overloads(root, source, language));
    issues.extend(check_explicit_rethrows(root, language));
    issues.extend(check_indexer_parameter_types(root, source, language));
    issues.extend(check_array_arguments_for_params_calls(root, language));
    issues.extend(check_readonly_primitive_fields(root, source, language));
    issues.extend(check_assembly_versions(root, source, language));
    issues.extend(check_public_list_signatures(root, source, language));
    issues.extend(check_collection_property_setters(root, source, language));
    issues.extend(check_debugger_display_references(root, source, language));
    issues
}

/// Methods that normalize text and must not fold case downwards.
const TO_LOWER_METHODS: [&str; 2] = ["ToLower", "ToLowerInvariant"];

/// csharpsquid:S4040 — normalization belongs in uppercase; lowercased
/// strings compare and hash differently across cultures.
fn check_lowercase_normalization(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| TO_LOWER_METHODS.contains(&callee_name(*call, source).unwrap_or("")))
        .map(|call| {
            issue(
                language,
                "S4040",
                "Use 'ToUpperInvariant' to normalize this string.",
                range_of(call),
            )
        })
        .collect()
}

/// csharpsquid:S4056 — culture-less `ToString`/`Parse` calls pick the
/// machine's locale instead of a stated one.
fn check_culture_less_conversions(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(call) {
            continue;
        }
        let arguments = invocation_arguments(call);
        let flagged = match callee_name(call, source) {
            Some("ToString") => arguments.is_empty(),
            Some("Parse") => arguments.len() == 1,
            _ => false,
        };
        if flagged {
            issues.push(issue(
                language,
                "S4056",
                "Call the overload that takes an 'IFormatProvider'.",
                range_of(call),
            ));
        }
    }
    issues
}

/// csharpsquid:S4058 — two-operand comparisons silently use the current
/// culture instead of a stated comparison mode.
fn check_culture_less_comparisons(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| {
            matches!(callee_name(*call, source), Some("Compare" | "Equals"))
                && invocation_arguments(*call).len() == 2
        })
        .map(|call| {
            issue(
                language,
                "S4058",
                "Use the 'StringComparison' overload of this comparison.",
                range_of(call),
            )
        })
        .collect()
}

/// csharpsquid:S1449 — searches and comparisons need an explicit culture or
fn check_culture_less_searches(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(call) {
            continue;
        }
        let count = invocation_arguments(call).len();
        let flagged = matches!(callee_name(call, source), Some("CompareTo") if count == 1)
            || matches!(callee_name(call, source), Some("IndexOf" | "LastIndexOf") if count <= 1);
        if flagged {
            issues.push(issue(
                language,
                "S1449",
                "Pass the culture or comparison type to this operation.",
                range_of(call),
            ));
        }
    }
    issues
}

/// The credential value inside a connection-string literal, if present.
fn embedded_password_value<'a>(literal_text: &'a str, lowered: &str) -> Option<&'a str> {
    for marker in ["password=", "pwd="] {
        if let Some(position) = lowered.find(marker) {
            let value_start = position + marker.len();
            let value_end = lowered[value_start..]
                .find(';')
                .map_or(lowered.len(), |relative| value_start + relative);
            return Some(literal_text[value_start..value_end].trim_matches('"'));
        }
    }
    None
}

/// csharpsquid:S2115 — hard-coded database passwords leak with the source.
fn check_hardcoded_connection_passwords(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for literal in string_literals(root) {
        if is_error_tainted(literal) {
            continue;
        }
        let inner = literal_inner_text(literal, source);
        let lowered = inner.to_ascii_lowercase();
        if !lowered.contains("password=") && !lowered.contains("pwd=") {
            continue;
        }
        if lowered.contains("integrated security") {
            continue;
        }
        if embedded_password_value(inner, &lowered).is_some_and(|value| !value.is_empty()) {
            issues.push(issue(
                language,
                "S2115",
                "Do not embed credentials in this connection string.",
                range_of(literal),
            ));
        }
    }
    issues
}

/// The guarded expression of a `lock (...)` statement.
fn lock_guard_expression(lock_statement: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = lock_statement.walk();
    let mut after_paren = false;
    for child in lock_statement.children(&mut cursor) {
        if child.kind() == "(" {
            after_paren = true;
            continue;
        }
        if after_paren {
            return (!child.kind().is_empty()).then_some(child);
        }
    }
    None
}
fn check_weak_identity_locks(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["lock_statement"])
        .into_iter()
        .filter(|lock_statement| !is_error_tainted(*lock_statement))
        .filter(|lock_statement| {
            lock_guard_expression(*lock_statement).is_some_and(|expression| {
                matches!(
                    expression.kind(),
                    "this" | "string_literal" | "typeof_expression"
                )
            })
        })
        .map(|lock_statement| {
            issue(
                language,
                "S3998",
                "Lock on a dedicated private lock object.",
                range_of(lock_statement),
            )
        })
        .collect()
}

/// csharpsquid:S6507 — locals are per-call, so locking on them guards
/// nothing shared.
fn check_locks_on_locals(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for lock_statement in collect_kinds(root, &["lock_statement"]) {
        if is_error_tainted(lock_statement) {
            continue;
        }
        let Some(expression) = lock_guard_expression(lock_statement) else {
            continue;
        };
        if expression.kind() != "identifier" {
            continue;
        }
        let name = node_text(expression, source);
        let local_lock = enclosing_method(lock_statement)
            .and_then(|method| body_of(method))
            .is_some_and(|body| {
                collect_kinds(body, &["variable_declarator"])
                    .iter()
                    .any(|declarator| {
                        declarator
                            .child_by_field_name("name")
                            .is_some_and(|declared| node_text(declared, source) == name)
                    })
            });
        if local_lock {
            issues.push(issue(
                language,
                "S6507",
                "Do not lock on this local variable.",
                range_of(lock_statement),
            ));
        }
    }
    issues
}

/// csharpsquid:S2445 — mutable lock fields invite swapped guards.
fn check_locks_on_mutable_fields(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for lock_statement in collect_kinds(root, &["lock_statement"]) {
        if is_error_tainted(lock_statement) {
            continue;
        }
        let Some(expression) = lock_guard_expression(lock_statement) else {
            continue;
        };
        if expression.kind() != "identifier" {
            continue;
        }
        let name = node_text(expression, source);
        let Some(owner) = enclosing_type(lock_statement) else {
            continue;
        };
        let field = type_members(owner)
            .into_iter()
            .find(|member| member.kind() == "field_declaration")
            .filter(|field_declaration| {
                field_declarator_names(*field_declaration, source).contains(&name)
            });
        let Some(field) = field else {
            continue;
        };
        if !has_modifier(&modifiers_of(field, source), "readonly") {
            issues.push(issue(
                language,
                "S2445",
                "Declare this lock field 'readonly'.",
                range_of(lock_statement),
            ));
        }
    }
    issues
}

/// Key-shaped member names (`Id`, `OrderKey`, ...).
fn key_shaped(name: &str) -> bool {
    name == "Id"
        || name == "Key"
        || (name.ends_with("Id") && name.len() > 2)
        || (name.ends_with("Key") && name.len() > 3)
}

/// csharpsquid:S3363 — date/time values make unstable, ambiguous keys.
fn check_datetime_key_members(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const DATETIME_TYPES: [&str; 2] = ["DateTime", "DateTimeOffset"];
    let mut issues = Vec::new();
    for property in collect_kinds(root, &["property_declaration"]) {
        if is_error_tainted(property) {
            continue;
        }
        let named_key = property
            .child_by_field_name("name")
            .is_some_and(|name| key_shaped(node_text(name, source)));
        let typed_datetime = property
            .child_by_field_name("type")
            .is_some_and(|type_node| {
                DATETIME_TYPES.contains(&simple_name(node_text(type_node, source)))
            });
        if named_key && typed_datetime {
            issues.push(issue(
                language,
                "S3363",
                "Do not use date/time types for this key member.",
                range_of(property),
            ));
        }
    }
    for field in collect_kinds(root, &["field_declaration"]) {
        if is_error_tainted(field) {
            continue;
        }
        let named_key = field_declarator_names(field, source)
            .into_iter()
            .any(key_shaped);
        let typed_datetime = collect_kinds(field, &["variable_declaration"])
            .first()
            .and_then(|declaration| first_named_child(*declaration))
            .is_some_and(|type_node| {
                DATETIME_TYPES.contains(&simple_name(node_text(type_node, source)))
            });
        if named_key && typed_datetime {
            issues.push(issue(
                language,
                "S3363",
                "Do not use date/time types for this key member.",
                range_of(field),
            ));
        }
    }
    issues
}

/// Base types from the pre-generic collections era.
const OUTDATED_BASE_TYPES: [&str; 8] = [
    "ArrayList",
    "Hashtable",
    "Queue",
    "Stack",
    "SortedList",
    "CollectionBase",
    "DictionaryBase",
    "ReadOnlyCollectionBase",
];

/// csharpsquid:S4052 — pre-generic collection bases lose type safety.
fn check_outdated_base_types(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &TYPE_DECLARATION_KINDS)
        .into_iter()
        .filter(|type_node| !is_error_tainted(*type_node))
        .filter(|type_node| {
            base_simple_names(*type_node, source)
                .iter()
                .any(|base| OUTDATED_BASE_TYPES.contains(base))
        })
        .map(|type_node| {
            issue(
                language,
                "S4052",
                "Replace this obsolete base type with a generic collection.",
                range_of(type_node),
            )
        })
        .collect()
}

/// Whether the invocation reads like an assertion call.
fn looks_like_assertion(invocation: Node<'_>, source: &str) -> bool {
    let Some(function) = invocation_function(invocation) else {
        return false;
    };
    let spelled = node_text(function, source).trim();
    spelled.contains("Assert")
        || callee_name(invocation, source).is_some_and(|name| {
            ["Should", "Verify", "Expect", "Check", "That"]
                .iter()
                .any(|prefix| name.starts_with(prefix))
        })
}

/// csharpsquid:S2699 — test methods without assertions verify nothing.
fn check_tests_include_assertions(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if !is_test_attributed(method, source) {
            continue;
        }
        let Some(body) = body_of(method) else {
            continue;
        };
        let asserts = collect_kinds(body, &["invocation_expression"])
            .iter()
            .any(|invocation| looks_like_assertion(*invocation, source));
        if !asserts {
            issues.push(issue(
                language,
                "S2699",
                "Add an assertion to this test method.",
                range_of(method),
            ));
        }
    }
    issues
}

/// csharpsquid:S2701 — literal assertions pass regardless of the code under
/// test.
fn check_literal_assertions(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const TRUE_ASSERT_METHODS: [&str; 2] = ["IsTrue", "True"];
    const FALSE_ASSERT_METHODS: [&str; 2] = ["IsFalse", "False"];
    let mut issues = Vec::new();
    for call in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(call) {
            continue;
        }
        let Some(name) = callee_name(call, source) else {
            continue;
        };
        let Some(first) = invocation_arguments(call).first().copied() else {
            continue;
        };
        let expression = argument_expression(first);
        let literal = if expression.kind() == "boolean_literal" {
            node_text(expression, source)
        } else {
            ""
        };
        let mismatched = (TRUE_ASSERT_METHODS.contains(&name) && literal == "true")
            || (FALSE_ASSERT_METHODS.contains(&name) && literal == "false");
        if mismatched {
            issues.push(issue(
                language,
                "S2701",
                "Remove the literal from this assertion.",
                range_of(call),
            ));
        }
    }
    issues
}

/// csharpsquid:S2970 — a constraint-less `Assert.That` asserts nothing.
fn check_unconstrained_assertions(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| invocation_targets(*call, source, Some("Assert"), &["That"]))
        .filter(|call| invocation_arguments(*call).len() == 1)
        .map(|call| {
            issue(
                language,
                "S2970",
                "Complete this 'Assert.That' with a constraint.",
                range_of(call),
            )
        })
        .collect()
}

/// MSTest-style assertion entry points carrying expected/actual pairs.
const PAIRED_ASSERT_METHODS: [&str; 4] = ["AreEqual", "AreNotEqual", "AreSame", "AreNotSame"];

/// Literal kinds that read as hard-coded expectations.
fn is_expectation_literal(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "integer_literal"
            | "real_literal"
            | "string_literal"
            | "character_literal"
            | "boolean_literal"
            | "verbatim_string_literal"
    )
}

/// csharpsquid:S3415 — expected values come first in paired assertions.
fn check_reversed_assertion_arguments(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(call) {
            continue;
        }
        if !PAIRED_ASSERT_METHODS.contains(&callee_name(call, source).unwrap_or("")) {
            continue;
        }
        let arguments = invocation_arguments(call);
        if arguments.len() < 2 {
            continue;
        }
        let first = argument_expression(arguments[0]);
        let second = argument_expression(arguments[1]);
        if first.kind() == "identifier" && is_expectation_literal(second) {
            issues.push(issue(
                language,
                "S3415",
                "Put the expected value first in this assertion.",
                range_of(call),
            ));
        }
    }
    issues
}

/// Attributes marking a type as a test container.
const TEST_CLASS_ATTRIBUTE_NAMES: [&str; 2] = ["TestClass", "TestFixture"];

/// csharpsquid:S2187 — annotated-but-empty test classes rot quietly.
fn check_test_classes_contain_tests(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["class_declaration"])
        .into_iter()
        .filter(|class_node| !is_error_tainted(*class_node))
        .filter(|class_node| {
            attributes_of(*class_node, source)
                .iter()
                .any(|name| TEST_CLASS_ATTRIBUTE_NAMES.contains(name))
        })
        .filter(|class_node| {
            member_declarations_of_kind(*class_node, "method_declaration")
                .iter()
                .all(|method| !is_test_attributed(*method, source))
        })
        .map(|class_node| {
            issue(
                language,
                "S2187",
                "Add test methods to this test class.",
                range_of(class_node),
            )
        })
        .collect()
}

/// csharpsquid:S4586 — non-async `Task` methods must not return null; there
/// is no completed task to await in null.
fn check_task_returns_null(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) || has_modifier(&modifiers_of(method, source), "async") {
            continue;
        }
        if simple_name(return_type_text(method, source)) != "Task" {
            continue;
        }
        let Some(body) = body_of(method) else {
            continue;
        };
        for statement in collect_kinds(body, &["return_statement"]) {
            let returns_null = first_named_child(statement)
                .is_some_and(|expression| expression.kind() == "null_literal");
            if returns_null {
                issues.push(issue(
                    language,
                    "S4586",
                    "Return 'Task.CompletedTask' instead of null.",
                    range_of(statement),
                ));
            }
        }
    }
    issues
}

/// Whether the body invokes `Dispose` with a literal argument.
fn calls_dispose_with_literal(body: Node<'_>, source: &str) -> bool {
    collect_kinds(body, &["invocation_expression"])
        .into_iter()
        .any(|call| {
            callee_name(call, source) == Some("Dispose") && invocation_arguments(call).len() == 1
        })
}

/// Dispose-shaped methods declared directly by a type.
fn dispose_methods<'t>(type_node: Node<'t>, source: &str) -> Vec<Node<'t>> {
    member_declarations_of_kind(type_node, "method_declaration")
        .into_iter()
        .filter(|method| {
            method
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source) == "Dispose")
        })
        .collect()
}

/// csharpsquid:S3881 — the full dispose pattern wires `Dispose`, a virtual
/// `Dispose(bool)`, and the finalizer together.
fn check_dispose_pattern(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if is_error_tainted(type_node)
            || !base_simple_names(type_node, source).contains(&"IDisposable")
        {
            continue;
        }
        let disposes = dispose_methods(type_node, source);
        let parameterless = disposes
            .iter()
            .copied()
            .find(|method| parameters_of(*method).is_empty());
        if disposes
            .iter()
            .all(|method| parameters_of(*method).len() != 1)
        {
            issues.push(issue(
                language,
                "S3881",
                "Add a 'Dispose(bool)' overload to complete the dispose pattern.",
                range_of(name_anchor(type_node)),
            ));
        }
        if let Some(dispose) = parameterless {
            let routes_through_bool =
                body_of(dispose).is_some_and(|body| calls_dispose_with_literal(body, source));
            if !routes_through_bool {
                issues.push(issue(
                    language,
                    "S3881",
                    "Route this 'Dispose' through 'Dispose(bool)'.",
                    range_of(dispose),
                ));
            }
        }
        for destructor in member_declarations_of_kind(type_node, "destructor_declaration") {
            let releases =
                body_of(destructor).is_some_and(|body| calls_dispose_with_literal(body, source));
            if !releases {
                issues.push(issue(
                    language,
                    "S3881",
                    "Call 'Dispose(false)' from this finalizer.",
                    range_of(destructor),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S2953 — a hand-rolled `Dispose` without `IDisposable` is
/// never called by `using`.
fn check_dispose_needs_interface(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &TYPE_DECLARATION_KINDS)
        .into_iter()
        .filter(|type_node| !is_error_tainted(*type_node))
        .filter(|type_node| !dispose_methods(*type_node, source).is_empty())
        .filter(|type_node| !base_simple_names(*type_node, source).contains(&"IDisposable"))
        .map(|type_node| {
            issue(
                language,
                "S2953",
                "Implement 'IDisposable' on this type.",
                range_of(name_anchor(type_node)),
            )
        })
        .collect()
}

/// csharpsquid:S1118 — utility classes are reached through their static
/// members, not through instances.
fn check_utility_class_constructors(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_node in collect_kinds(root, &["class_declaration"]) {
        if is_error_tainted(class_node) {
            continue;
        }
        let methods = member_declarations_of_kind(class_node, "method_declaration");
        if methods.is_empty()
            || !methods
                .iter()
                .all(|method| has_modifier(&modifiers_of(*method, source), "static"))
        {
            continue;
        }
        let fields_hold_state = type_members(class_node)
            .into_iter()
            .filter(|member| matches!(member.kind(), "field_declaration"))
            .any(|field| {
                let modifiers = modifiers_of(field, source);
                !has_modifier(&modifiers, "static") && !has_modifier(&modifiers, "const")
            });
        if fields_hold_state {
            continue;
        }
        for constructor in member_declarations_of_kind(class_node, "constructor_declaration") {
            let modifiers = modifiers_of(constructor, source);
            if has_modifier(&modifiers, "public") || has_modifier(&modifiers, "internal") {
                issues.push(issue(
                    language,
                    "S1118",
                    "Hide this constructor or declare the class 'static'.",
                    range_of(constructor),
                ));
            }
        }
    }
    issues
}

/// Reserved exception types that carry no domain meaning.
const RESERVED_EXCEPTION_TYPES: [&str; 3] =
    ["Exception", "ApplicationException", "SystemException"];

/// csharpsquid:S112 — reserved exception types say nothing about the
/// failure and force callers to over-catch.
fn check_reserved_exception_throws(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["object_creation_expression"])
        .into_iter()
        .filter(|creation| !is_error_tainted(*creation))
        .filter(|creation| {
            RESERVED_EXCEPTION_TYPES.contains(&simple_name(creation_type_text(*creation, source)))
        })
        .map(|creation| {
            issue(
                language,
                "S112",
                "Throw a more specific exception than this reserved type.",
                range_of(creation),
            )
        })
        .collect()
}

/// Comment markers that promise unfinished work.
fn comment_tag_issues(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> (Vec<Issue>, Vec<Issue>) {
    let mut fixmes = Vec::new();
    let mut todos = Vec::new();
    for comment in collect_kinds(root, &["comment"]) {
        let upper = node_text(comment, source).to_ascii_uppercase();
        if upper.contains("FIXME") {
            fixmes.push(issue(
                language,
                "S1134",
                "Track the work promised by this FIXME tag.",
                range_of(comment),
            ));
        }
        if upper.contains("TODO") {
            todos.push(issue(
                language,
                "S1135",
                "Track the work promised by this TODO tag.",
                range_of(comment),
            ));
        }
    }
    (fixmes, todos)
}

/// csharpsquid:S1163 — throwing from `finally` swallows in-flight failures.
fn check_throws_in_finally(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["throw_statement"])
        .into_iter()
        .filter(|throw| ancestors_of(*throw).any(|ancestor| ancestor.kind() == "finally_clause"))
        .map(|throw| {
            issue(
                language,
                "S1163",
                "Do not throw from a finally block.",
                range_of(throw),
            )
        })
        .collect()
}

/// The declared exception type name of a catch clause (`ex` of
/// `catch (Exception ex)`), when present.
fn catch_type_tail<'a>(clause: Node<'_>, source: &'a str) -> Option<&'a str> {
    let mut cursor = clause.walk();
    let declaration = clause
        .children(&mut cursor)
        .find(|child| child.kind() == "catch_declaration")?;
    let type_node = declaration.child_by_field_name("type")?;
    Some(simple_name(node_text(type_node, source)))
}

/// csharpsquid:S1696 — catching `NullReferenceException` hides dereference
/// bugs.
fn check_null_reference_catches(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["catch_clause"])
        .into_iter()
        .filter(|clause| !is_error_tainted(*clause))
        .filter(|clause| catch_type_tail(*clause, source) == Some("NullReferenceException"))
        .map(|clause| {
            issue(
                language,
                "S1696",
                "Do not catch 'NullReferenceException'.",
                range_of(clause),
            )
        })
        .collect()
}

/// csharpsquid:S2139 — logging and rethrowing reports the failure twice.
fn check_double_reported_catches(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["catch_clause"])
        .into_iter()
        .filter(|clause| !is_error_tainted(*clause))
        .filter_map(|clause| {
            let body = clause.child_by_field_name("body")?;
            Some((
                clause,
                !logging_calls(body, source).is_empty(),
                !collect_kinds(body, &["throw_statement"]).is_empty(),
            ))
        })
        .filter(|(_, logs, rethrows)| *logs && *rethrows)
        .map(|(clause, _, _)| {
            issue(
                language,
                "S2139",
                "Choose either logging or rethrowing in this catch clause.",
                range_of(clause),
            )
        })
        .collect()
}

/// csharpsquid:S2221 — catching bare `Exception` also swallows unrelated
/// runtime failures.
fn check_general_exception_catches(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["catch_clause"])
        .into_iter()
        .filter(|clause| !is_error_tainted(*clause))
        .filter(|clause| catch_type_tail(*clause, source) == Some("Exception"))
        .map(|clause| {
            issue(
                language,
                "S2221",
                "Catch a more specific exception than 'Exception'.",
                range_of(clause),
            )
        })
        .collect()
}

/// csharpsquid:S2291 — `unchecked` around `Sum` silently truncates.
fn check_unchecked_sums(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["checked_statement"])
        .into_iter()
        .filter(|statement| !is_error_tainted(*statement))
        .filter(|statement| first_child_token_text(*statement, source) == "unchecked")
        .filter(|statement| {
            collect_kinds(*statement, &["invocation_expression"])
                .into_iter()
                .any(|call| callee_name(call, source) == Some("Sum"))
        })
        .map(|statement| {
            issue(
                language,
                "S2291",
                "Do not disable overflow checks around 'Sum'.",
                range_of(statement),
            )
        })
        .collect()
}

/// Whether the text parses as a plain identifier usable with `nameof`.
fn is_identifier_text(text: &str) -> bool {
    let mut characters = text.chars();
    match characters.next() {
        Some(first) if first.is_alphabetic() || first == '_' => {}
        _ => return false,
    }
    characters.all(|rest| rest.is_alphanumeric() || rest == '_')
}

/// csharpsquid:S2302 — strings that mirror an enclosing parameter name
/// should travel through `nameof`.
fn check_strings_matching_parameters(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for literal in string_literals(root) {
        if is_error_tainted(literal) {
            continue;
        }
        let inner = literal_inner_text(literal, source);
        if !is_identifier_text(inner) {
            continue;
        }
        let mirrors_parameter = enclosing_method(literal).is_some_and(|method| {
            parameters_of(method).iter().any(|parameter| {
                parameter
                    .child_by_field_name("name")
                    .is_some_and(|name| node_text(name, source) == inner)
            })
        });
        if mirrors_parameter {
            issues.push(issue(
                language,
                "S2302",
                format!("Replace this string with 'nameof({inner})'."),
                range_of(literal),
            ));
        }
    }
    issues
}

/// Catch and finally handler signature of a try statement, as written.
fn try_handler_signature(try_statement: Node<'_>, source: &str) -> (Vec<String>, Option<String>) {
    let mut cursor = try_statement.walk();
    let mut catches = Vec::new();
    let mut fin = None;
    for child in try_statement.children(&mut cursor) {
        match child.kind() {
            "catch_clause" => catches.push(node_text(child, source).trim().to_string()),
            "finally_clause" => fin = Some(node_text(child, source).trim().to_string()),
            _ => {}
        }
    }
    (catches, fin)
}

/// csharpsquid:S2327 — adjacent identical handlers merge into one `try`.
fn check_mergeable_try_statements(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for block in collect_kinds(root, &["block"]) {
        for pair in block_statements(block).windows(2) {
            if pair[0].kind() != "try_statement" || pair[1].kind() != "try_statement" {
                continue;
            }
            if try_handler_signature(pair[0], source) == try_handler_signature(pair[1], source) {
                issues.push(issue(
                    language,
                    "S2327",
                    "Merge these try statements sharing identical handlers.",
                    range_of(pair[1]),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S2333 — single-part `partial` types and accessors repeating
/// their property's visibility carry dead modifiers.
fn check_redundant_modifiers(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    use std::collections::BTreeMap;
    let declarations = collect_kinds(root, &TYPE_DECLARATION_KINDS);
    let mut name_counts: BTreeMap<(String, String), u32> = BTreeMap::new();
    for type_node in &declarations {
        let key = (
            (*type_node).kind().to_string(),
            type_node
                .child_by_field_name("name")
                .map(|name| node_text(name, source).to_string())
                .unwrap_or_default(),
        );
        *name_counts.entry(key).or_insert(0) += 1;
    }
    let mut issues = Vec::new();
    for type_node in &declarations {
        if is_error_tainted(*type_node)
            || !has_modifier(&modifiers_of(*type_node, source), "partial")
        {
            continue;
        }
        let key = (
            (*type_node).kind().to_string(),
            type_node
                .child_by_field_name("name")
                .map(|name| node_text(name, source).to_string())
                .unwrap_or_default(),
        );
        if name_counts.get(&key).copied().unwrap_or(0) == 1 {
            issues.push(issue(
                language,
                "S2333",
                "Remove this redundant 'partial' modifier.",
                range_of(name_anchor(*type_node)),
            ));
        }
    }
    for property in collect_kinds(root, &["property_declaration"]) {
        let property_rank = accessibility_rank(&modifiers_of(property, source));
        if property_rank == 0 {
            continue;
        }
        for accessor in accessors_of(property) {
            if accessibility_rank(&modifiers_of(accessor, source)) == property_rank {
                issues.push(issue(
                    language,
                    "S2333",
                    "Remove this redundant accessibility modifier.",
                    range_of(accessor),
                ));
            }
        }
    }
    issues
}

/// Return shapes valid for test methods.
const TEST_RETURN_TYPES: [&str; 3] = ["void", "Task", "ValueTask"];

/// csharpsquid:S3433 — runners only invoke public `void`/`Task` test
/// methods.
fn check_test_method_signatures(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if !is_test_attributed(method, source) {
            continue;
        }
        if !has_modifier(&modifiers_of(method, source), "public") {
            issues.push(issue(
                language,
                "S3433",
                "Make this test method public.",
                range_of(method),
            ));
        }
        let returns = simple_name(return_type_text(method, source));
        if !TEST_RETURN_TYPES.contains(&returns) {
            issues.push(issue(
                language,
                "S3433",
                "Test methods must not return values.",
                range_of(method),
            ));
        }
    }
    issues
}

/// csharpsquid:S2486 — swallowing bare `Exception` hides unrelated bugs.
fn check_ignored_generic_exceptions(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["catch_clause"])
        .into_iter()
        .filter(|clause| !is_error_tainted(*clause))
        .filter(|clause| catch_type_tail(*clause, source) == Some("Exception"))
        .filter(|clause| {
            clause
                .child_by_field_name("body")
                .is_some_and(|body| block_statements(body).is_empty())
        })
        .map(|clause| {
            issue(
                language,
                "S2486",
                "Handle this exception or narrow the catch clause.",
                range_of(clause),
            )
        })
        .collect()
}
/// csharpsquid:S2737 — a catch clause that only rethrows adds nothing.
fn check_rethrow_only_catches(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["catch_clause"])
        .into_iter()
        .filter(|clause| !is_error_tainted(*clause))
        .filter(|clause| {
            clause.child_by_field_name("body").is_some_and(|body| {
                let statements = block_statements(body);
                statements.len() == 1 && statements[0].kind() == "throw_statement"
            })
        })
        .map(|clause| {
            issue(
                language,
                "S2737",
                "Handle this exception or remove this catch clause.",
                range_of(clause),
            )
        })
        .collect()
}

/// Whether the line carries the transposed `= +` operator pair outside a
/// comment.
fn has_transposed_assignment(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("/*") {
        return false;
    }
    let bytes = line.as_bytes();
    for index in 1..bytes.len().saturating_sub(1) {
        if bytes[index] != b'=' || bytes.get(index + 1) != Some(&b'+') {
            continue;
        }
        let before = bytes[index - 1];
        let not_other_operator = !matches!(
            before,
            b'=' | b'+' | b'-' | b'*' | b'/' | b'%' | b'<' | b'>' | b'!' | b'|' | b'&' | b'^'
        );
        if not_other_operator {
            return true;
        }
    }
    false
}

/// csharpsquid:S2757 — `= +` is two operators where one was meant.
fn check_transposed_operators(source: &str, language: CsLanguage) -> Vec<Issue> {
    source
        .lines()
        .enumerate()
        .filter(|(_, line)| has_transposed_assignment(line))
        .map(|(index, line)| {
            issue(
                language,
                "S2757",
                "Fix this mistyped assignment operator.",
                hoonarqube_ir::Range {
                    start: hoonarqube_ir::Pos {
                        line: to_u32(index) + 1,
                        column: 0,
                    },
                    end: hoonarqube_ir::Pos {
                        line: to_u32(index) + 1,
                        column: to_u32(line.chars().count()),
                    },
                },
            )
        })
        .collect()
}

/// csharpsquid:S3217 — casting the iteration variable per body statement
/// means the sequence should be typed up front.
fn check_foreach_iteration_casts(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for each in collect_kinds(root, &["foreach_statement"]) {
        if is_error_tainted(each) {
            continue;
        }
        let Some(loop_variable) = each.child_by_field_name("left") else {
            continue;
        };
        let name = node_text(loop_variable, source);
        let Some(body) = each.child_by_field_name("body") else {
            continue;
        };
        for cast in collect_kinds(body, &["cast_expression"]) {
            let casts_variable = cast.child_by_field_name("value").is_some_and(|operand| {
                operand.kind() == "identifier" && node_text(operand, source) == name
            });
            if casts_variable {
                issues.push(issue(
                    language,
                    "S3217",
                    "Iterate with the correct element type instead of casting.",
                    range_of(cast),
                ));
            }
        }
    }
    issues
}

/// Whether the argument subtree computes something (`f()`, `x++`, `a = b`).
fn argument_has_side_effects(argument: Node<'_>, source: &str) -> bool {
    !collect_kinds(
        argument,
        &["invocation_expression", "assignment_expression"],
    )
    .is_empty()
        || collect_kinds(
            argument,
            &["prefix_unary_expression", "postfix_unary_expression"],
        )
        .into_iter()
        .any(|unary| {
            let mut cursor = unary.walk();
            unary
                .children(&mut cursor)
                .any(|child| !child.is_named() && matches!(node_text(child, source), "++" | "--"))
        })
}

/// csharpsquid:S3346 — assertions that compute hide failures when stripped.
fn check_pure_debug_assertions(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(call) || !invocation_targets(call, source, Some("Debug"), &["Assert"]) {
            continue;
        }
        let impure = invocation_arguments(call)
            .iter()
            .any(|argument| argument_has_side_effects(*argument, source));
        if impure {
            issues.push(issue(
                language,
                "S3346",
                "Keep side effects out of 'Debug.Assert'.",
                range_of(call),
            ));
        }
    }
    issues
}

/// Mandatory and optional parameter counts of a method.
fn parameter_shape(method: Node<'_>) -> (usize, usize) {
    let parameters = parameters_of(method);
    let optional = parameters.iter().filter(|parameter| {
        let mut cursor = parameter.walk();
        parameter.named_children(&mut cursor).count() > 2
    });
    (parameters.len(), optional.count())
}

/// csharpsquid:S3427 — overlapping defaults make some call sites ambiguous.
fn check_overlapping_optional_overloads(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for methods in methods_grouped_by_name(root, source).into_values() {
        if methods.len() < 2 {
            continue;
        }
        let shapes: Vec<(usize, usize)> = methods
            .iter()
            .map(|method| parameter_shape(*method))
            .collect();
        for first in 0..methods.len() {
            for second in (first + 1)..methods.len() {
                let (params_first, optional_first) = shapes[first];
                let (params_second, optional_second) = shapes[second];
                let lower = params_first
                    .saturating_sub(optional_first)
                    .max(params_second.saturating_sub(optional_second));
                let upper = params_first.min(params_second);
                let ambiguous = lower <= upper
                    && (params_first != params_second || optional_first > 0 || optional_second > 0);
                if ambiguous {
                    issues.push(issue(
                        language,
                        "S3427",
                        "Remove the ambiguity between these overloads.",
                        range_of(name_anchor(methods[second])),
                    ));
                }
            }
        }
    }
    issues
}

/// csharpsquid:S3445 — `throw ex;` restarts the stack trace at the catch.
fn check_explicit_rethrows(source_root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(source_root, &["throw_statement"])
        .into_iter()
        .filter(|throw| !is_error_tainted(*throw))
        .filter(|throw| {
            first_named_child(*throw).is_some_and(|expression| expression.kind() == "identifier")
        })
        .map(|throw| {
            issue(
                language,
                "S3445",
                "Use a bare 'throw;' statement to rethrow.",
                range_of(throw),
            )
        })
        .collect()
}

/// Types acceptable for indexer parameters.
const INDEXER_PARAMETER_TYPES: [&str; 12] = [
    "string", "String", "int", "uint", "long", "ulong", "short", "ushort", "byte", "sbyte", "char",
    "nint",
];

/// csharpsquid:S3876 — indexers on other types read as opaque lookups.
fn check_indexer_parameter_types(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["indexer_declaration"])
        .into_iter()
        .filter(|indexer| !is_error_tainted(*indexer))
        .filter(|indexer| {
            indexer
                .child_by_field_name("parameters")
                .is_some_and(|list| {
                    parameters_from_list(list).iter().any(|parameter| {
                        parameter
                            .child_by_field_name("type")
                            .is_some_and(|type_node| {
                                !INDEXER_PARAMETER_TYPES
                                    .contains(&simple_name(node_text(type_node, source)))
                            })
                    })
                })
        })
        .map(|indexer| {
            issue(
                language,
                "S3876",
                "Index on a string or integral type.",
                range_of(indexer),
            )
        })
        .collect()
}

/// Parameters behind either bracketed or parenthesized lists.
fn parameters_from_list(list: Node<'_>) -> Vec<Node<'_>> {
    collect_kinds(list, &["parameter"])
}

/// csharpsquid:S3878 — arrays built just to feed a `params` call waste an
/// allocation.
fn check_array_arguments_for_params_calls(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .flat_map(|call| invocation_arguments(call))
        .filter(|argument| {
            matches!(
                argument_expression(*argument).kind(),
                "array_creation_expression" | "implicit_array_creation_expression"
            )
        })
        .map(|argument| {
            issue(
                language,
                "S3878",
                "Pass the elements individually to this 'params' call.",
                range_of(argument),
            )
        })
        .collect()
}

/// Built-in types whose readonly fields read as constants.
const PRIMITIVE_FIELD_TYPES: [&str; 13] = [
    "int", "uint", "long", "ulong", "short", "ushort", "byte", "sbyte", "char", "bool", "double",
    "float", "decimal",
];

/// csharpsquid:S3887 — public readonly primitive literals are constants.
fn check_readonly_primitive_fields(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for field in collect_kinds(root, &["field_declaration"]) {
        if is_error_tainted(field) {
            continue;
        }
        let modifiers = modifiers_of(field, source);
        if !has_modifier(&modifiers, "readonly")
            || has_modifier(&modifiers, "static")
            || has_modifier(&modifiers, "const")
            || !has_any_accessibility(&modifiers)
            || has_modifier(&modifiers, "private")
        {
            continue;
        }
        let typed_primitive = collect_kinds(field, &["variable_declaration"])
            .first()
            .and_then(|declaration| first_named_child(*declaration))
            .is_some_and(|type_node| {
                PRIMITIVE_FIELD_TYPES.contains(&simple_name(node_text(type_node, source)))
            });
        if !typed_primitive {
            continue;
        }
        let literal_initialized =
            collect_kinds(field, &["variable_declarator"])
                .iter()
                .all(|declarator| {
                    declarator
                        .child_by_field_name("name")
                        .and_then(|name| declarator_initializer(*declarator, name))
                        .is_some_and(is_literal_node)
                });
        if literal_initialized {
            issues.push(issue(
                language,
                "S3887",
                "Declare this constant field 'const' instead of 'readonly'.",
                range_of(field),
            ));
        }
    }
    issues
}

/// csharpsquid:S3904 — assemblies should state their version.
fn check_assembly_versions(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let names = assembly_attribute_names(root, source);
    if names.is_empty()
        || names
            .iter()
            .any(|name| name.to_ascii_lowercase().contains("version"))
    {
        return Vec::new();
    }
    vec![file_level_issue(
        language,
        "S3904",
        "Add assembly version information ([assembly: AssemblyVersion(\"1.0.0.0\")]).",
    )]
}

/// csharpsquid:S3956 — concrete `List<T>` leaks implementation details from
/// public signatures.
fn check_public_list_signatures(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const LIST_MARKER: &str = "List<";
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) || !has_modifier(&modifiers_of(method, source), "public") {
            continue;
        }
        let exposes_list = return_type_text(method, source).contains(LIST_MARKER)
            || parameters_of(method).iter().any(|parameter| {
                parameter
                    .child_by_field_name("type")
                    .is_some_and(|type_node| node_text(type_node, source).contains(LIST_MARKER))
            });
        if exposes_list {
            issues.push(issue(
                language,
                "S3956",
                "Expose 'IEnumerable<T>' or 'IList<T>' instead of 'List<T>'.",
                range_of(name_anchor(method)),
            ));
        }
    }
    for member_kind in ["property_declaration", "field_declaration"] {
        for member in collect_kinds(root, &[member_kind]) {
            if is_error_tainted(member) || !has_modifier(&modifiers_of(member, source), "public") {
                continue;
            }
            let typed_list = match member.kind() {
                "property_declaration" => member
                    .child_by_field_name("type")
                    .is_some_and(|type_node| node_text(type_node, source).contains(LIST_MARKER)),
                _ => collect_kinds(member, &["variable_declaration"])
                    .iter()
                    .any(|declaration| {
                        first_named_child(*declaration).is_some_and(|type_node| {
                            node_text(type_node, source).contains(LIST_MARKER)
                        })
                    }),
            };
            if typed_list {
                issues.push(issue(
                    language,
                    "S3956",
                    "Expose 'IEnumerable<T>' or 'IList<T>' instead of 'List<T>'.",
                    range_of(member),
                ));
            }
        }
    }
    issues
}

/// Collection spellings whose properties should not carry setters.
const COLLECTION_TYPE_MARKERS: [&str; 4] = ["List<", "Dictionary<", "Collection<", "[]"];

/// csharpsquid:S4004 — callers mutate collections through the property's
/// value, so setters only invite replacement.
fn check_collection_property_setters(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["property_declaration"])
        .into_iter()
        .filter(|property| !is_error_tainted(*property))
        .filter(|property| {
            property
                .child_by_field_name("type")
                .is_some_and(|type_node| {
                    COLLECTION_TYPE_MARKERS
                        .iter()
                        .any(|marker| node_text(type_node, source).contains(marker))
                })
        })
        .filter(|property| {
            accessors_of(*property)
                .iter()
                .any(|accessor| accessor_keyword(*accessor, source) == "set")
        })
        .map(|property| {
            issue(
                language,
                "S4004",
                "Make this collection property read-only.",
                range_of(property),
            )
        })
        .collect()
}

/// `{Member}` references inside a `DebuggerDisplay` value.
fn debugger_display_members(value: &str) -> Vec<&str> {
    let mut members = Vec::new();
    let mut rest = value;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        match after.find('}') {
            Some(close) => {
                let token = &after[..close];
                let bare = token.split([',', ':', '(']).next().unwrap_or(token).trim();
                if !bare.is_empty() {
                    members.push(bare);
                }
                rest = &after[close + 1..];
            }
            None => break,
        }
    }
    members
}

/// csharpsquid:S4545 — `DebuggerDisplay` values naming missing members
/// render blank output.
fn check_debugger_display_references(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for list in collect_kinds(root, &["attribute_list"]) {
        if is_error_tainted(list) {
            continue;
        }
        let mut cursor = list.walk();
        let display = list.children(&mut cursor).find(|attribute| {
            attribute
                .child_by_field_name("name")
                .is_some_and(|name| simple_name(node_text(name, source)) == "DebuggerDisplay")
        });
        let Some(display) = display else {
            continue;
        };
        let Some(literal) = collect_kinds(display, &["string_literal"]).first().copied() else {
            continue;
        };
        let Some(owner) = list.parent().filter(|parent| {
            TYPE_DECLARATION_KINDS.contains(&parent.kind())
                || CALLABLE_BODY_OWNER_KINDS.contains(&parent.kind())
        }) else {
            continue;
        };
        let known = declared_member_names(owner, source);
        for member in debugger_display_members(literal_inner_text(literal, source)) {
            if !known.contains(member) {
                issues.push(issue(
                    language,
                    "S4545",
                    format!("'DebuggerDisplay' references missing member '{member}'."),
                    range_of(list),
                ));
            }
        }
    }
    issues
}

/// Field, property, and method names declared directly by a declaration.
fn declared_member_names(declaration: Node<'_>, source: &str) -> std::collections::HashSet<String> {
    let mut names = declared_method_names(declaration, source);
    names.extend(field_and_property_names(declaration, source));
    names
}

// ======================================================================
// Tier B — file-scoped usage analysis
//
// One symbol-table pass feeds these rules: every declared member with its
// owning type, every identifier occurrence classified as binding or use,
// and every field write site. ERROR-tainted subtrees contribute nothing,
// so broken sources stay silent.
// ======================================================================

/// Member-level declarations owning data or executable bodies. Deliberately
/// skips `accessor_declaration`, so lookups resolve to the whole property.
const TIER_B_MEMBER_KINDS: [&str; 6] = [
    "method_declaration",
    "constructor_declaration",
    "destructor_declaration",
    "operator_declaration",
    "property_declaration",
    "indexer_declaration",
];

/// Flavors of tracked member declarations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemberFlavor {
    Field,
    EventField,
    Method,
    Property,
}

impl MemberFlavor {
    fn word(self) -> &'static str {
        match self {
            Self::Field => "field",
            Self::EventField => "event",
            Self::Method => "method",
            Self::Property => "property",
        }
    }
}

/// One tracked member declaration with its owning type.
struct MemberSymbol<'t> {
    flavor: MemberFlavor,
    name: &'t str,
    declaration: Node<'t>,
    anchor: Node<'t>,
    owner: Node<'t>,
    nested_type: bool,
    is_static_or_const: bool,
    has_initializer: bool,
}

/// One type declaration with its nearest enclosing type.
struct TypeSymbol<'t> {
    declaration: Node<'t>,
    parent: Option<Node<'t>>,
}

/// One identifier occurrence, classified as binding introduction or use.
struct Reference<'t> {
    name: &'t str,
    node: Node<'t>,
    introduces_binding: bool,
}

/// One field write site (`x = …`, `x += …`, `++x`, `x--`, `this.x = …`).
struct WriteSite<'t> {
    name: &'t str,
    node: Node<'t>,
}

/// File-scoped declarations and usages shared by the Tier-B checks.
struct UsageSymbols<'t> {
    types: Vec<TypeSymbol<'t>>,
    members: Vec<MemberSymbol<'t>>,
    references: Vec<Reference<'t>>,
    writes: Vec<WriteSite<'t>>,
}

impl<'t> UsageSymbols<'t> {
    fn uses_of(&self, name: &str) -> Vec<Node<'t>> {
        self.references
            .iter()
            .filter(|reference| reference.name == name && !reference.introduces_binding)
            .map(|reference| reference.node)
            .collect()
    }

    fn writes_of(&self, name: &str) -> Vec<Node<'t>> {
        self.writes
            .iter()
            .filter(|site| site.name == name)
            .map(|site| site.node)
            .collect()
    }

    fn member_names_of(&self, owner: Node<'t>) -> std::collections::HashSet<&'t str> {
        self.members
            .iter()
            .filter(|member| member.owner == owner)
            .map(|member| member.name)
            .collect()
    }

    fn static_members_of(&self, owner: Node<'t>) -> Vec<&MemberSymbol<'t>> {
        self.members
            .iter()
            .filter(|member| member.owner == owner && member.is_static_or_const)
            .collect()
    }
}

fn build_usage_symbols<'t>(root: Node<'t>, source: &'t str) -> UsageSymbols<'t> {
    let mut symbols = UsageSymbols {
        types: Vec::new(),
        members: Vec::new(),
        references: Vec::new(),
        writes: Vec::new(),
    };
    collect_usage_symbols(root, None, source, &mut symbols);
    symbols
}

fn collect_usage_symbols<'t>(
    node: Node<'t>,
    type_owner: Option<Node<'t>>,
    source: &'t str,
    symbols: &mut UsageSymbols<'t>,
) {
    if node.is_error() || node.is_missing() {
        return;
    }
    let mut inner_owner = type_owner;
    if TYPE_DECLARATION_KINDS.contains(&node.kind()) {
        symbols.types.push(TypeSymbol {
            declaration: node,
            parent: type_owner,
        });
        collect_declared_members(node, type_owner.is_some(), source, symbols);
        inner_owner = Some(node);
    } else if node.kind() == "identifier" {
        symbols.references.push(Reference {
            name: node_text(node, source),
            node,
            introduces_binding: introduces_binding(node),
        });
    } else if let Some(site) = write_site(node, source) {
        symbols.writes.push(site);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_usage_symbols(child, inner_owner, source, symbols);
    }
}

/// Whether an identifier introduces a declaration instead of referencing
/// an existing one: declaration names, variables, parameters, catch vars.
fn introduces_binding(identifier: Node<'_>) -> bool {
    let Some(parent) = identifier.parent() else {
        return false;
    };
    let kind = parent.kind();
    if matches!(
        kind,
        "variable_declarator" | "parameter" | "catch_declaration" | "enum_member_declaration"
    ) {
        return true;
    }
    kind.ends_with("_declaration") && parent.child_by_field_name("name") == Some(identifier)
}

/// The field a write expression targets: bare identifiers and `this.x`.
fn write_target_name<'a>(target: Node<'_>, source: &'a str) -> Option<&'a str> {
    match target.kind() {
        "identifier" => Some(node_text(target, source)),
        "member_access_expression" => {
            let mut cursor = target.walk();
            let named: Vec<Node> = target
                .children(&mut cursor)
                .filter(tree_sitter::Node::is_named)
                .collect();
            let receiver = named.first()?;
            let name = named.last()?;
            (receiver.kind() == "this_expression" && name.kind() == "identifier")
                .then(|| node_text(*name, source))
        }
        _ => None,
    }
}

/// Classifies an expression as a field write site when possible.
fn write_site<'t>(node: Node<'t>, source: &'t str) -> Option<WriteSite<'t>> {
    let target = match node.kind() {
        "assignment_expression" => binary_operands(node)?.0,
        "prefix_unary_expression" | "postfix_unary_expression" => {
            let mut cursor = node.walk();
            let increments = node
                .children(&mut cursor)
                .any(|child| !child.is_named() && matches!(child.kind(), "++" | "--"));
            if !increments {
                return None;
            }
            first_named_child(node)?
        }
        _ => return None,
    };
    let name = write_target_name(target, source)?;
    Some(WriteSite { name, node })
}

/// Registers the members declared directly by a type declaration.
fn collect_declared_members<'t>(
    type_node: Node<'t>,
    nested: bool,
    source: &'t str,
    symbols: &mut UsageSymbols<'t>,
) {
    for member in type_members(type_node) {
        let flavor = match member.kind() {
            "field_declaration" => MemberFlavor::Field,
            "event_field_declaration" => MemberFlavor::EventField,
            "method_declaration" => MemberFlavor::Method,
            "property_declaration" => MemberFlavor::Property,
            _ => continue,
        };
        let modifiers = modifiers_of(member, source);
        let is_static_or_const =
            has_modifier(&modifiers, "static") || has_modifier(&modifiers, "const");
        if matches!(flavor, MemberFlavor::Field | MemberFlavor::EventField) {
            for declarator in collect_kinds(member, &["variable_declarator"]) {
                let Some(anchor) = declarator.child_by_field_name("name").or_else(|| {
                    collect_kinds(declarator, &["identifier"])
                        .into_iter()
                        .next()
                }) else {
                    continue;
                };
                let mut declarator_cursor = declarator.walk();
                let has_initializer = declarator
                    .named_children(&mut declarator_cursor)
                    .any(|child| child.id() != anchor.id());
                symbols.members.push(MemberSymbol {
                    flavor,
                    name: node_text(anchor, source),
                    declaration: member,
                    anchor,
                    owner: type_node,
                    nested_type: nested,
                    is_static_or_const,
                    has_initializer,
                });
            }
        } else {
            let Some(anchor) = member.child_by_field_name("name") else {
                continue;
            };
            symbols.members.push(MemberSymbol {
                flavor,
                name: node_text(anchor, source),
                declaration: member,
                anchor,
                owner: type_node,
                nested_type: nested,
                is_static_or_const,
                has_initializer: false,
            });
        }
    }
}

/// Nearest ancestor among `kinds`, if any.
fn nearest_ancestor_of_kinds<'t>(node: Node<'t>, kinds: &[&str]) -> Option<Node<'t>> {
    ancestors_of(node).find(|ancestor| kinds.contains(&ancestor.kind()))
}

/// Effective private visibility: explicit modifiers win, nested members
/// default to private, top-level ones to internal.
fn is_private_member(declaration: Node<'_>, source: &str, nested_type: bool) -> bool {
    let modifiers = modifiers_of(declaration, source);
    if modifiers
        .iter()
        .any(|modifier| matches!(*modifier, "public" | "internal" | "protected"))
    {
        return false;
    }
    has_modifier(&modifiers, "private") || nested_type
}

/// Modifiers tying a member to inheritance or tooling contracts, where
/// usage-based rules must stay silent.
fn has_contract_modifier(modifiers: &[&str]) -> bool {
    modifiers.iter().any(|modifier| {
        matches!(
            *modifier,
            "override" | "virtual" | "abstract" | "extern" | "new" | "partial"
        )
    })
}

/// Whether the owning type is `partial` and may have siblings in other
/// files holding extra references.
fn owner_is_partial(member_owner: Node<'_>, source: &str) -> bool {
    has_modifier(&modifiers_of(member_owner, source), "partial")
}

/// Whether the reference passes its identifier by `ref` or `out`, hiding
/// an assignment from the write index.
fn is_ref_or_out_argument(reference: Node<'_>, source: &str) -> bool {
    reference
        .parent()
        .filter(|parent| parent.kind() == "argument")
        .is_some_and(|argument| {
            matches!(
                node_text(argument, source).split_whitespace().next(),
                Some("ref" | "out")
            )
        })
}

/// Whether a write lands in a constructor compatible with the field's
/// staticity, the only place a field becomes safely `readonly`.
fn is_matching_constructor_write(write: Node<'_>, field_is_static: bool, source: &str) -> bool {
    let Some(owner) = nearest_ancestor_of_kinds(write, &TIER_B_MEMBER_KINDS) else {
        return false;
    };
    owner.kind() == "constructor_declaration"
        && has_modifier(&modifiers_of(owner, source), "static") == field_is_static
}

/// Whether the member declares executable code (blocks or expression
/// arrows), separating real members from auto-properties.
fn declares_executable_code(declaration: Node<'_>) -> bool {
    !collect_kinds(declaration, &["block", "arrow_expression_clause"]).is_empty()
}

/// Whether the member touches instance state: sibling member references
/// or `this` anywhere in its declaration span.
fn touches_instance_data(member: &MemberSymbol<'_>, symbols: &UsageSymbols<'_>) -> bool {
    let span = member.declaration.byte_range();
    let owner_names = symbols.member_names_of(member.owner);
    let sibling_reference = symbols.references.iter().any(|reference| {
        let reference_span = reference.node.byte_range();
        reference_span.start >= span.start
            && reference_span.end <= span.end
            && !reference.introduces_binding
            && reference.name != member.name
            && owner_names.contains(reference.name)
    });
    sibling_reference || !collect_kinds(member.declaration, &["this_expression"]).is_empty()
}

/// csharpsquid:S4487 — private members nobody references are dead weight.
fn check_unreferenced_private_members(
    source: &str,
    language: CsLanguage,
    symbols: &UsageSymbols<'_>,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for member in &symbols.members {
        let modifiers = modifiers_of(member.declaration, source);
        if !is_private_member(member.declaration, source, member.nested_type)
            || has_contract_modifier(&modifiers)
            || is_attributed(member.declaration, source)
            || owner_is_partial(member.owner, source)
            || member.name == "Main"
            || (member.flavor == MemberFlavor::Method
                && has_explicit_interface_specifier(member.declaration))
            || !symbols.uses_of(member.name).is_empty()
        {
            continue;
        }
        issues.push(issue(
            language,
            "S4487",
            format!(
                "Remove the unused private {} '{}'.",
                member.flavor.word(),
                member.name
            ),
            range_of(member.anchor),
        ));
    }
    issues
}

/// csharpsquid:S1450 — fields touched by exactly one method behave like
/// locals and belong in that method.
fn check_single_method_fields(
    source: &str,
    language: CsLanguage,
    symbols: &UsageSymbols<'_>,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for member in &symbols.members {
        if member.flavor != MemberFlavor::Field
            || !is_private_member(member.declaration, source, member.nested_type)
            || has_modifier(&modifiers_of(member.declaration, source), "const")
            || is_attributed(member.declaration, source)
            || owner_is_partial(member.owner, source)
        {
            continue;
        }
        let uses = symbols.uses_of(member.name);
        if uses.is_empty() {
            continue;
        }
        let mut homes: Vec<Option<Node>> = uses
            .iter()
            .map(|use_site| nearest_ancestor_of_kinds(*use_site, &TIER_B_MEMBER_KINDS))
            .collect();
        homes.sort_by_key(|home| home.map(|owner| owner.byte_range().start));
        homes.dedup_by_key(|home| home.map(|owner| owner.byte_range().start));
        let single_method = matches!(homes.as_slice(), [Some(home)]
            if home.kind() == "method_declaration");
        if single_method {
            issues.push(issue(
                language,
                "S1450",
                format!(
                    "Field '{}' is used only within one method; make it a local variable instead.",
                    member.name
                ),
                range_of(member.anchor),
            ));
        }
    }
    issues
}

/// csharpsquid:S3459 — private fields that are read but never assigned.
fn check_unassigned_private_fields(
    source: &str,
    language: CsLanguage,
    symbols: &UsageSymbols<'_>,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for member in &symbols.members {
        if member.flavor != MemberFlavor::Field
            || !is_private_member(member.declaration, source, member.nested_type)
            || has_modifier(&modifiers_of(member.declaration, source), "const")
            || is_attributed(member.declaration, source)
            || owner_is_partial(member.owner, source)
            || member.has_initializer
            || !symbols.writes_of(member.name).is_empty()
            || symbols.uses_of(member.name).is_empty()
        {
            continue;
        }
        issues.push(issue(
            language,
            "S3459",
            format!(
                "Remove unassigned field '{}' or assign it a value.",
                member.name
            ),
            range_of(member.anchor),
        ));
    }
    issues
}

/// csharpsquid:S2933 — private fields written only from constructors can
/// carry the `readonly` promise.
fn check_readonly_field_candidates(
    source: &str,
    language: CsLanguage,
    symbols: &UsageSymbols<'_>,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for member in &symbols.members {
        let modifiers = modifiers_of(member.declaration, source);
        if member.flavor != MemberFlavor::Field
            || !is_private_member(member.declaration, source, member.nested_type)
            || has_modifier(&modifiers, "readonly")
            || has_modifier(&modifiers, "const")
            || is_attributed(member.declaration, source)
            || owner_is_partial(member.owner, source)
        {
            continue;
        }
        let writes = symbols.writes_of(member.name);
        if writes.is_empty() && !member.has_initializer {
            continue;
        }
        if symbols
            .uses_of(member.name)
            .iter()
            .any(|use_site| is_ref_or_out_argument(*use_site, source))
        {
            continue;
        }
        let field_is_static = has_modifier(&modifiers, "static");
        if writes
            .iter()
            .all(|write| is_matching_constructor_write(*write, field_is_static, source))
        {
            issues.push(issue(
                language,
                "S2933",
                format!("Make field '{}' 'readonly'.", member.name),
                range_of(member.anchor),
            ));
        }
    }
    issues
}

/// csharpsquid:S2325 — private members ignoring instance data can become
/// `static`; public ones stay untouched because callers outside the file
/// invoke them through instances.
fn check_static_candidate_members(
    source: &str,
    language: CsLanguage,
    symbols: &UsageSymbols<'_>,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for member in &symbols.members {
        if !matches!(member.flavor, MemberFlavor::Method | MemberFlavor::Property)
            || !matches!(
                member.owner.kind(),
                "class_declaration" | "struct_declaration"
            )
            || !base_simple_names(member.owner, source).is_empty()
            || owner_is_partial(member.owner, source)
            || is_attributed(member.declaration, source)
            || !is_private_member(member.declaration, source, member.nested_type)
            || has_modifier(&modifiers_of(member.declaration, source), "static")
            || has_contract_modifier(&modifiers_of(member.declaration, source))
            || !declares_executable_code(member.declaration)
            || touches_instance_data(member, symbols)
        {
            continue;
        }
        issues.push(issue(
            language,
            "S2325",
            format!(
                "'{}' does not access instance data and can be marked 'static'.",
                member.name
            ),
            range_of(member.anchor),
        ));
    }
    issues
}

/// csharpsquid:S2696 — instance members must not write shared static state.
fn check_instance_writes_to_static_fields(
    source: &str,
    language: CsLanguage,
    symbols: &UsageSymbols<'_>,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for site in &symbols.writes {
        let Some(field) = symbols.members.iter().find(|member| {
            member.flavor == MemberFlavor::Field
                && member.name == site.name
                && has_modifier(&modifiers_of(member.declaration, source), "static")
        }) else {
            continue;
        };
        if has_modifier(&modifiers_of(field.declaration, source), "const") {
            continue;
        }
        let Some(context) = nearest_ancestor_of_kinds(site.node, &TIER_B_MEMBER_KINDS) else {
            continue;
        };
        if context.kind() == "constructor_declaration"
            || has_modifier(&modifiers_of(context, source), "static")
        {
            continue;
        }
        issues.push(issue(
            language,
            "S2696",
            format!(
                "Static field '{}' should not be written from an instance member.",
                site.name
            ),
            range_of(site.node),
        ));
    }
    issues
}

/// csharpsquid:S3218 — nested types redeclaring an outer static member
/// hide it and mislead readers.
fn check_inner_statics_shadowing_outer(
    language: CsLanguage,
    symbols: &UsageSymbols<'_>,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_symbol in &symbols.types {
        let Some(mut ancestor) = type_symbol.parent else {
            continue;
        };
        let mut outer_names = symbols.static_members_of(ancestor);
        while let Some(grandparent) = symbols
            .types
            .iter()
            .find(|candidate| candidate.declaration == ancestor)
            .and_then(|candidate| candidate.parent)
        {
            ancestor = grandparent;
            outer_names.extend(symbols.static_members_of(grandparent));
        }
        for member in symbols.static_members_of(type_symbol.declaration) {
            if outer_names.iter().any(|outer| outer.name == member.name) {
                issues.push(issue(
                    language,
                    "S3218",
                    format!(
                        "Rename '{}'; it hides a static member of an outer type.",
                        member.name
                    ),
                    range_of(member.anchor),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S3398 — private methods referenced exclusively from nested
/// types belong beside their callers.
fn check_private_methods_called_only_from_nested_types(
    source: &str,
    language: CsLanguage,
    symbols: &UsageSymbols<'_>,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for member in &symbols.members {
        if member.flavor != MemberFlavor::Method
            || !is_private_member(member.declaration, source, member.nested_type)
            || is_attributed(member.declaration, source)
            || owner_is_partial(member.owner, source)
            || member.name == "Main"
        {
            continue;
        }
        let uses = symbols.uses_of(member.name);
        if uses.is_empty() {
            continue;
        }
        let owner_span = member.owner.byte_range();
        let all_nested = uses.iter().all(|use_site| {
            nearest_ancestor_of_kinds(*use_site, &TYPE_DECLARATION_KINDS).is_some_and(|holder| {
                holder != member.owner
                    && holder.byte_range().start >= owner_span.start
                    && holder.byte_range().end <= owner_span.end
            })
        });
        if all_nested {
            issues.push(issue(
                language,
                "S3398",
                format!(
                    "Private method '{}' is only called from nested types.",
                    member.name
                ),
                range_of(member.anchor),
            ));
        }
    }
    issues
}

/// Collection type heads whose members should yield empty values, not `null`.
const COLLECTION_TYPE_NAMES: [&str; 16] = [
    "List",
    "Dictionary",
    "HashSet",
    "SortedSet",
    "SortedDictionary",
    "IEnumerable",
    "ICollection",
    "IList",
    "IDictionary",
    "IReadOnlyCollection",
    "IReadOnlyList",
    "IReadOnlyDictionary",
    "Queue",
    "Stack",
    "LinkedList",
    "ReadOnlyCollection",
];

/// Whether a return-type node denotes an array or collection.
fn is_collection_return(returns: Node<'_>, source: &str) -> bool {
    let text = node_text(returns, source).trim();
    text.ends_with("[]") || COLLECTION_TYPE_NAMES.contains(&simple_name(text))
}

/// csharpsquid:S1168 — collection-returning methods return empty, not null.
fn check_null_returns_from_collection_members(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method)
            || has_modifier(&modifiers_of(method, source), "override")
            || !method
                .child_by_field_name("returns")
                .is_some_and(|returns| is_collection_return(returns, source))
            || enclosing_type(method)
                .is_some_and(|owner| !base_simple_names(owner, source).is_empty())
        {
            continue;
        }
        let body = body_of(method);
        let mut flagged = false;
        if let Some(body) = body {
            for return_statement in collect_kinds(body, &["return_statement"]) {
                if is_error_tainted(return_statement)
                    || first_named_child(return_statement)
                        .is_none_or(|expression| expression.kind() != "null_literal")
                {
                    continue;
                }
                issues.push(issue(
                    language,
                    "S1168",
                    "Return an empty collection instead of null.",
                    range_of(return_statement),
                ));
                flagged = true;
            }
        }
        if body.is_some() || flagged {
            continue;
        }
        for arrow in collect_kinds(method, &["arrow_expression_clause"]) {
            if !is_error_tainted(arrow)
                && first_named_child(arrow)
                    .is_some_and(|expression| expression.kind() == "null_literal")
            {
                issues.push(issue(
                    language,
                    "S1168",
                    "Return an empty collection instead of null.",
                    range_of(arrow),
                ));
            }
        }
    }
    issues
}

/// The assignment overwriting `variable` before any read within `scope`.
fn ignored_initial_value<'t>(scope: Node<'t>, variable: &str, source: &str) -> Option<Node<'t>> {
    let mut references: Vec<Node> = collect_kinds(scope, &["identifier"])
        .into_iter()
        .filter(|candidate| {
            !is_error_tainted(*candidate) && node_text(*candidate, source) == variable
        })
        .collect();
    references.sort_by_key(|node| node.byte_range().start);
    let first = *references.first()?;
    let assignment = first
        .parent()
        .filter(|parent| parent.kind() == "assignment_expression")?;
    if operator_of(assignment) != Some("=") {
        return None;
    }
    let (left, right) = binary_operands(assignment)?;
    if left.id() != first.id()
        || collect_kinds(right, &["identifier"])
            .iter()
            .any(|identifier| node_text(*identifier, source) == variable)
    {
        return None;
    }
    Some(assignment)
}

/// csharpsquid:S1226 — parameters and caught exceptions keep their initial
/// value only until something reads them.
fn check_ignored_initial_values(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    let flag = |issues: &mut Vec<Issue>, assignment: Node<'_>, name: &str| {
        issues.push(issue(
            language,
            "S1226",
            format!("'{name}' is overwritten before its initial value is ever read."),
            range_of(assignment),
        ));
    };
    for callable in collect_kinds(root, &CALLABLE_BODY_OWNER_KINDS) {
        if is_error_tainted(callable) {
            continue;
        }
        let Some(body) = body_of(callable) else {
            continue;
        };
        for parameter in parameters_of(callable) {
            if is_error_tainted(parameter)
                || modifiers_of(parameter, source)
                    .iter()
                    .any(|modifier| matches!(*modifier, "ref" | "out" | "in"))
            {
                continue;
            }
            let Some(name_node) = parameter.child_by_field_name("name") else {
                continue;
            };
            if let Some(assignment) =
                ignored_initial_value(body, node_text(name_node, source), source)
            {
                flag(&mut issues, assignment, node_text(name_node, source));
            }
        }
    }
    for catch_clause in collect_kinds(root, &["catch_clause"]) {
        if is_error_tainted(catch_clause) {
            continue;
        }
        if let Some((assignment, name)) = catch_offender(catch_clause, source) {
            flag(&mut issues, assignment, name);
        }
    }
    issues
}

/// `(assignment, variable)` overwriting a caught exception unread.
fn catch_offender<'a>(catch_clause: Node<'a>, source: &'a str) -> Option<(Node<'a>, &'a str)> {
    if is_error_tainted(catch_clause) {
        return None;
    }
    let declaration = collect_kinds(catch_clause, &["catch_declaration"])
        .into_iter()
        .next()?;
    let block = collect_kinds(catch_clause, &["block"]).into_iter().next()?;
    let name_node = declaration.child_by_field_name("name")?;
    let name = node_text(name_node, source);
    Some((ignored_initial_value(block, name, source)?, name))
}

/// csharpsquid:S1699 — constructors must not dispatch overridable members.
fn check_constructors_calling_overridable_members(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    symbols: &UsageSymbols<'_>,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for constructor in collect_kinds(root, &["constructor_declaration"]) {
        if is_error_tainted(constructor) {
            continue;
        }
        let owner = enclosing_type(constructor);
        let overridable: std::collections::HashSet<&str> = symbols
            .members
            .iter()
            .filter(|member| {
                member.flavor == MemberFlavor::Method
                    && owner.is_some_and(|owner| member.owner == owner)
                    && !has_modifier(&modifiers_of(member.declaration, source), "static")
                    && modifiers_of(member.declaration, source)
                        .iter()
                        .any(|modifier| matches!(*modifier, "virtual" | "abstract"))
            })
            .map(|member| member.name)
            .collect();
        let Some(body) = body_of(constructor) else {
            continue;
        };
        for invocation in collect_kinds(body, &["invocation_expression"]) {
            if is_error_tainted(invocation) {
                continue;
            }
            let Some(callee) = callee_name(invocation, source) else {
                continue;
            };
            if overridable.contains(callee) {
                issues.push(issue(
                    language,
                    "S1699",
                    format!("Constructor calls overridable method '{callee}'."),
                    range_of(invocation),
                ));
            }
        }
    }
    issues
}

/// Unconstrained generic parameter names of one declaration.
fn unconstrained_generic_parameters(
    declaration: Node<'_>,
    source: &str,
) -> Option<std::collections::HashSet<String>> {
    let (list, _) = type_parameter_list_of(declaration)?;
    let mut unconstrained: std::collections::HashSet<String> = collect_kinds(list, &["identifier"])
        .into_iter()
        .map(|identifier| node_text(identifier, source).to_string())
        .collect();
    if unconstrained.is_empty() {
        return None;
    }
    let mut cursor = declaration.walk();
    for child in declaration.children(&mut cursor) {
        if child.kind() != "type_parameter_constraints_clause" {
            continue;
        }
        let clause = node_text(child, source);
        if let Some((head, tail)) = clause.split_once(':') {
            let constrained = tail
                .split(',')
                .map(str::trim)
                .filter_map(|bound| bound.split_whitespace().next())
                .any(|bound| matches!(bound, "class" | "struct" | "notnull"));
            if !constrained {
                continue;
            }
            let Some(name) = head.split_whitespace().last() else {
                continue;
            };
            unconstrained.remove(name);
        }
    }
    (!unconstrained.is_empty()).then_some(unconstrained)
}

/// Names of parameters and locals typed by an unconstrained generic
/// parameter of their enclosing declaration.
fn unconstrained_generic_value_names(
    root: Node<'_>,
    source: &str,
) -> std::collections::HashSet<String> {
    let mut declarations = collect_kinds(root, &TYPE_DECLARATION_KINDS);
    declarations.extend(collect_kinds(root, &["method_declaration"]));
    let mut values = std::collections::HashSet::new();
    for declaration in declarations {
        if is_error_tainted(declaration) {
            continue;
        }
        let Some(generic_names) = unconstrained_generic_parameters(declaration, source) else {
            continue;
        };
        for region in signature_regions(declaration) {
            for parameter in collect_kinds(region, &["parameter"]) {
                let Some(type_node) = parameter.child_by_field_name("type") else {
                    continue;
                };
                if !generic_names.contains(simple_name(node_text(type_node, source))) {
                    continue;
                }
                let Some(name) = parameter.child_by_field_name("name") else {
                    continue;
                };
                values.insert(node_text(name, source).to_string());
            }
        }
        for variable_declaration in collect_kinds(declaration, &["variable_declaration"]) {
            let Some(type_node) = variable_declaration.child_by_field_name("type") else {
                continue;
            };
            if !generic_names.contains(simple_name(node_text(type_node, source))) {
                continue;
            }
            for declarator in collect_kinds(variable_declaration, &["variable_declarator"]) {
                if let Some(name) = declarator.child_by_field_name("name") {
                    values.insert(node_text(name, source).to_string());
                }
            }
        }
    }
    values
}

/// csharpsquid:S2955 — unconstrained generic values mislead `null` checks.
fn check_generic_null_comparisons(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let values = unconstrained_generic_value_names(root, source);
    let mut issues = Vec::new();
    for (expression, left, right) in comparisons(root) {
        if !matches!(operator_of(expression), Some("==" | "!=")) {
            continue;
        }
        for operand in [left, right] {
            if operand.kind() != "identifier"
                || !values.contains(node_text(operand, source))
                || [left, right]
                    .iter()
                    .all(|side| (*side).kind() != "null_literal")
            {
                continue;
            }
            issues.push(issue(
                language,
                "S2955",
                format!(
                    "Constrain '{}' or avoid comparing it with null.",
                    node_text(operand, source)
                ),
                range_of(expression),
            ));
        }
    }
    issues
}

/// csharpsquid:S2997 — disposables returned from inside their own `using`.
fn check_using_disposable_returned(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for using_statement in collect_kinds(root, &["using_statement"]) {
        if is_error_tainted(using_statement) {
            continue;
        }
        let resource = collect_kinds(using_statement, &["variable_declaration"])
            .into_iter()
            .next();
        let body = collect_kinds(using_statement, &["block"])
            .into_iter()
            .next();
        let (Some(resource), Some(body)) = (resource, body) else {
            continue;
        };
        for declarator in collect_kinds(resource, &["variable_declarator"]) {
            let Some(name) = declarator.child_by_field_name("name") else {
                continue;
            };
            let creates_disposable = declarator_initializer(declarator, name)
                .is_some_and(|initializer| initializer.kind() == "object_creation_expression");
            if !creates_disposable {
                continue;
            }
            for return_statement in collect_kinds(body, &["return_statement"]) {
                let returns_variable =
                    first_named_child(return_statement).is_some_and(|expression| {
                        expression.kind() == "identifier"
                            && node_text(expression, source) == node_text(name, source)
                    });
                if returns_variable {
                    issues.push(issue(
                        language,
                        "S2997",
                        format!(
                            "'{}' is disposed by its using statement; return it from outside.",
                            node_text(name, source)
                        ),
                        range_of(return_statement),
                    ));
                }
            }
        }
    }
    issues
}

/// `StringBuilder` members that mutate instead of yielding content.
const STRING_BUILDER_MUTATIONS: [&str; 7] = [
    "Append",
    "AppendLine",
    "AppendFormat",
    "Insert",
    "Remove",
    "Clear",
    "Replace",
];

/// Whether a reference reads a builder's content instead of mutating it.
fn consumes_string_builder(reference: Node<'_>, source: &str) -> bool {
    let Some(parent) = reference.parent() else {
        return true;
    };
    let invocation = parent.parent().filter(|grandparent| {
        parent.kind() == "member_access_expression"
            && grandparent.kind() == "invocation_expression"
            && invocation_function(*grandparent)
                .is_some_and(|function| function.id() == parent.id())
    });
    if let Some(invocation) = invocation {
        return !callee_name(invocation, source)
            .is_some_and(|callee| STRING_BUILDER_MUTATIONS.contains(&callee));
    }
    matches!(
        parent.kind(),
        "argument" | "return_statement" | "element_access_expression"
    )
}

/// csharpsquid:S3063 — builders nobody ever turns into output.
fn check_unconsumed_string_builders(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    symbols: &UsageSymbols<'_>,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for declarator in collect_kinds(root, &["variable_declarator"]) {
        if is_error_tainted(declarator) {
            continue;
        }
        let container = declarator
            .parent()
            .and_then(|declaration| declaration.parent());
        if matches!(container, Some(container) if matches!(container.kind(), "field_declaration" | "event_field_declaration"))
        {
            continue;
        }
        let Some(name) = declarator.child_by_field_name("name") else {
            continue;
        };
        let builds_content = declarator_initializer(declarator, name).is_some_and(|initializer| {
            initializer
                .child_by_field_name("type")
                .is_some_and(|type_node| {
                    simple_name(node_text(type_node, source)) == "StringBuilder"
                })
        });
        if !builds_content {
            continue;
        }
        let uses: Vec<Node> = symbols
            .uses_of(node_text(name, source))
            .into_iter()
            .filter(|use_site| use_site.byte_range().start > declarator.byte_range().end)
            .collect();
        if uses.is_empty()
            || uses
                .iter()
                .any(|use_site| consumes_string_builder(*use_site, source))
        {
            continue;
        }
        issues.push(issue(
            language,
            "S3063",
            format!(
                "The content of StringBuilder '{}' is never consumed.",
                node_text(name, source)
            ),
            range_of(declarator),
        ));
    }
    issues
}

/// Delegate type names declared in the file.
fn declared_delegate_names<'a>(
    root: Node<'a>,
    source: &'a str,
) -> std::collections::HashSet<&'a str> {
    collect_kinds(root, &["delegate_declaration"])
        .into_iter()
        .filter_map(|declaration| declaration.child_by_field_name("name"))
        .map(|name| node_text(name, source))
        .collect()
}

/// Whether a declared type spells a delegate: in-file delegates or common
/// handler suffixes.
fn is_delegate_type_name(
    type_name: Option<&str>,
    delegates: &std::collections::HashSet<&str>,
) -> bool {
    type_name.is_some_and(|name| {
        delegates.contains(name)
            || name.ends_with("Delegate")
            || name.ends_with("Handler")
            || name.ends_with("Callback")
            || name.ends_with("EventHandler")
    })
}

/// Explicitly typed variables as `(name, declared simple type)` pairs.
fn typed_variables<'a>(root: Node<'a>, source: &'a str) -> Vec<(&'a str, &'a str)> {
    collect_kinds(root, &["variable_declarator"])
        .into_iter()
        .filter_map(|declarator| {
            let name = declarator.child_by_field_name("name")?;
            let declaration = declarator.parent()?;
            let type_node = declaration.child_by_field_name("type")?;
            Some((
                node_text(name, source),
                simple_name(node_text(type_node, source)),
            ))
        })
        .collect()
}

/// csharpsquid:S3172 — delegate subtraction hides removed handlers.
fn check_delegate_subtraction(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let delegates = declared_delegate_names(root, source);
    let variables = typed_variables(root, source);
    let mut issues = Vec::new();
    for binary in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(binary) || operator_of(binary) != Some("-") {
            continue;
        }
        let Some((left, right)) = binary_operands(binary) else {
            continue;
        };
        if left.kind() != "identifier" || expression_name(right, source).is_none() {
            continue;
        }
        let name = node_text(left, source);
        let delegate_typed = variables
            .iter()
            .filter(|(variable, _)| *variable == name)
            .any(|(_, type_name)| is_delegate_type_name(Some(type_name), &delegates));
        if delegate_typed {
            issues.push(issue(
                language,
                "S3172",
                "Subtracting delegates silently removes handlers; unsubscribe with '-=' instead.",
                range_of(binary),
            ));
        }
    }
    issues
}

/// The invocation an identifier participates in as callee, if any.
fn invocation_callee_site(reference: Node<'_>) -> Option<Node<'_>> {
    let parent = reference.parent()?;
    if parent.kind() == "invocation_expression" && invocation_function(parent) == Some(reference) {
        return Some(parent);
    }
    if parent.kind() == "member_access_expression" {
        let grandparent = parent.parent()?;
        if grandparent.kind() == "invocation_expression"
            && invocation_function(grandparent) == Some(parent)
        {
            return Some(grandparent);
        }
    }
    None
}

/// Whether an invocation's result evaporates: statement position only.
fn discards_result(invocation: Node<'_>) -> bool {
    let mut current = invocation;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "parenthesized_expression" => current = parent,
            "expression_statement" => return true,
            _ => return false,
        }
    }
    false
}

/// csharpsquid:S3241 — private results nobody captures.
fn check_discarded_return_values(
    source: &str,
    language: CsLanguage,
    symbols: &UsageSymbols<'_>,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for member in &symbols.members {
        let modifiers = modifiers_of(member.declaration, source);
        if member.flavor != MemberFlavor::Method
            || !is_private_member(member.declaration, source, member.nested_type)
            || has_contract_modifier(&modifiers)
            || is_attributed(member.declaration, source)
            || owner_is_partial(member.owner, source)
            || member.name == "Main"
            || member
                .declaration
                .child_by_field_name("returns")
                .is_none_or(|returns| node_text(returns, source).trim() == "void")
        {
            continue;
        }
        let call_sites: Vec<Node> = symbols
            .uses_of(member.name)
            .into_iter()
            .filter_map(invocation_callee_site)
            .collect();
        if call_sites.is_empty() || !call_sites.iter().all(|site| discards_result(*site)) {
            continue;
        }
        issues.push(issue(
            language,
            "S3241",
            format!(
                "No caller uses the return value of '{}'; make it 'void' or capture the result.",
                member.name
            ),
            range_of(member.anchor),
        ));
    }
    issues
}

/// Gathers every Tier-B usage-analysis issue from the shared symbol table.
fn usage_analysis_issues<'t>(root: Node<'t>, source: &'t str, language: CsLanguage) -> Vec<Issue> {
    let symbols = build_usage_symbols(root, source);
    let mut issues = Vec::new();
    issues.extend(check_unreferenced_private_members(
        source, language, &symbols,
    ));
    issues.extend(check_single_method_fields(source, language, &symbols));
    issues.extend(check_unassigned_private_fields(source, language, &symbols));
    issues.extend(check_readonly_field_candidates(source, language, &symbols));
    issues.extend(check_static_candidate_members(source, language, &symbols));
    issues.extend(check_instance_writes_to_static_fields(
        source, language, &symbols,
    ));
    issues.extend(check_inner_statics_shadowing_outer(language, &symbols));
    issues.extend(check_private_methods_called_only_from_nested_types(
        source, language, &symbols,
    ));
    issues.extend(check_null_returns_from_collection_members(
        root, source, language,
    ));
    issues.extend(check_ignored_initial_values(root, source, language));
    issues.extend(check_constructors_calling_overridable_members(
        root, source, language, &symbols,
    ));
    issues.extend(check_generic_null_comparisons(root, source, language));
    issues.extend(check_using_disposable_returned(root, source, language));
    issues.extend(check_unconsumed_string_builders(
        root, source, language, &symbols,
    ));
    issues.extend(check_delegate_subtraction(root, source, language));
    issues.extend(check_explicit_caller_information_arguments(
        root, source, language,
    ));
    issues.extend(check_static_initialization_order(
        source, language, &symbols,
    ));
    issues.extend(check_bitwise_non_flags_enums(root, source, language));
    issues.extend(check_this_escaping_constructors(root, language));
    issues.extend(check_gettype_on_type_instances(root, source, language));
    issues.extend(check_unvalidated_public_parameters(root, source, language));
    issues.extend(check_string_uri_overload_delegation(root, source, language));
    issues.extend(check_disposable_types_with_finalizers(
        root, source, language,
    ));
    issues.extend(check_accessor_backing_field_mismatch(
        root, source, language,
    ));
    issues.extend(check_discarded_return_values(source, language, &symbols));
    issues
}

/// Attributes whose arguments the compiler fills in automatically.
const CALLER_INFORMATION_ATTRIBUTES: [&str; 3] =
    ["CallerMemberName", "CallerFilePath", "CallerLineNumber"];

/// csharpsquid:S3236 — caller-information arguments are supplied by the
/// compiler and must not be spelled out at call sites.
fn check_explicit_caller_information_arguments(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) {
            continue;
        }
        let parameters = parameters_of(method);
        let supplied_by_compiler = parameters
            .iter()
            .filter(|parameter| {
                has_any_attribute(**parameter, source, &CALLER_INFORMATION_ATTRIBUTES)
            })
            .count();
        if supplied_by_compiler == 0 || supplied_by_compiler >= parameters.len() {
            continue;
        }
        let expected = parameters.len() - supplied_by_compiler;
        let Some(name) = method.child_by_field_name("name") else {
            continue;
        };
        for invocation in collect_kinds(root, &["invocation_expression"]) {
            if callee_name(invocation, source) != Some(node_text(name, source)) {
                continue;
            }
            let arguments = invocation_arguments(invocation);
            if arguments.len() <= expected {
                continue;
            }
            issues.push(issue(
                language,
                "S3236",
                "Omit this caller-information argument; the compiler supplies it.",
                range_of(arguments[expected]),
            ));
        }
    }
    issues
}

/// csharpsquid:S3263 — static field initializers reading later static
/// fields depend on unspecified initialization order.
fn check_static_initialization_order(
    source: &str,
    language: CsLanguage,
    symbols: &UsageSymbols<'_>,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_symbol in &symbols.types {
        let static_fields: Vec<&MemberSymbol> = symbols
            .members
            .iter()
            .filter(|member| {
                member.owner == type_symbol.declaration
                    && member.flavor == MemberFlavor::Field
                    && member.is_static_or_const
                    && !has_modifier(&modifiers_of(member.declaration, source), "const")
            })
            .collect();
        for field in &static_fields {
            let Some(declarator) = field.anchor.parent() else {
                continue;
            };
            let Some(name) = declarator.child_by_field_name("name") else {
                continue;
            };
            let Some(initializer) = declarator_initializer(declarator, name) else {
                continue;
            };
            let initializer_start = field.anchor.byte_range().start;
            for reference in collect_kinds(initializer, &["identifier"]) {
                let referenced = node_text(reference, source);
                if referenced == field.name
                    || !static_fields.iter().any(|sibling| {
                        sibling.name == referenced
                            && sibling.anchor.byte_range().start > initializer_start
                    })
                {
                    continue;
                }
                issues.push(issue(
                    language,
                    "S3263",
                    format!(
                        "'{referenced}' is declared after '{}'; static initialization order makes this read unreliable.",
                        field.name
                    ),
                    range_of(reference),
                ));
            }
        }
    }
    issues
}

/// Non-`[Flags]` enum type names declared in the file plus the names of
/// their members.
fn non_flags_enum_names<'a>(
    root: Node<'a>,
    source: &'a str,
) -> (
    std::collections::HashSet<&'a str>,
    std::collections::HashSet<&'a str>,
) {
    let mut types = std::collections::HashSet::new();
    let mut members = std::collections::HashSet::new();
    for enum_node in collect_kinds(root, &["enum_declaration"]) {
        if has_attribute(&attributes_of(enum_node, source), "Flags") {
            continue;
        }
        if let Some(name) = enum_node.child_by_field_name("name") {
            types.insert(node_text(name, source));
        }
        for body_child in collect_kinds(enum_node, &["enum_member_declaration"]) {
            if let Some(name) = body_child.child_by_field_name("name") {
                members.insert(node_text(name, source));
            }
        }
    }
    (types, members)
}

/// The bitwise operator of a binary or assignment expression.
fn bitwise_operator(expression: Node<'_>) -> Option<&'static str> {
    const OPERATORS: [&str; 6] = ["|", "&", "^", "|=", "&=", "^="];
    let mut cursor = expression.walk();
    let kind = expression
        .children(&mut cursor)
        .find(|child| !child.is_named())?
        .kind();
    OPERATORS
        .iter()
        .find(|operator| **operator == kind)
        .copied()
}

/// csharpsquid:S3265 — bitwise operations need `[Flags]` enums.
fn check_bitwise_non_flags_enums(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let (enum_types, enum_members) = non_flags_enum_names(root, source);
    if enum_types.is_empty() {
        return Vec::new();
    }
    let mut value_names = enum_members;
    for (variable, type_name) in typed_variables(root, source) {
        if enum_types.contains(type_name) {
            value_names.insert(variable);
        }
    }
    for parameter in collect_kinds(root, &["parameter"]) {
        let Some(type_node) = parameter.child_by_field_name("type") else {
            continue;
        };
        if !enum_types.contains(simple_name(node_text(type_node, source))) {
            continue;
        }
        let Some(name) = parameter.child_by_field_name("name") else {
            continue;
        };
        value_names.insert(node_text(name, source));
    }
    let mut issues = Vec::new();
    let mut expressions = collect_kinds(root, &["binary_expression"]);
    expressions.extend(collect_kinds(root, &["assignment_expression"]));
    for expression in expressions {
        if is_error_tainted(expression) || bitwise_operator(expression).is_none() {
            continue;
        }
        let touches_enum = collect_kinds(expression, &["identifier"])
            .iter()
            .any(|identifier| value_names.contains(node_text(*identifier, source)));
        if touches_enum {
            issues.push(issue(
                language,
                "S3265",
                "This enum is not marked [Flags]; avoid bitwise operations on its values.",
                range_of(expression),
            ));
        }
    }
    issues
}

/// csharpsquid:S3366 — constructors must not publish `this` early.
fn check_this_escaping_constructors(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for constructor in collect_kinds(root, &["constructor_declaration"]) {
        if is_error_tainted(constructor) {
            continue;
        }
        let Some(body) = body_of(constructor) else {
            continue;
        };
        let mut this_sites: Vec<Node> = Vec::new();
        walk_all(body, &mut |node| {
            if matches!(node.kind(), "this" | "this_expression") {
                this_sites.push(node);
            }
        });
        for this_expression in this_sites {
            let Some(parent) = this_expression.parent() else {
                continue;
            };
            let escapes = match parent.kind() {
                "argument" | "return_statement" => true,
                "assignment_expression" => binary_operands(parent)
                    .is_some_and(|(_, right)| right.id() == this_expression.id()),
                _ => false,
            };
            if escapes {
                issues.push(issue(
                    language,
                    "S3366",
                    "Constructor leaks 'this' before the object is fully initialized.",
                    range_of(this_expression),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S3443 — `GetType()` on a `System.Type` instance is noise.
fn check_gettype_on_type_instances(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for outer in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(outer) || callee_name(outer, source) != Some("GetType") {
            continue;
        }
        let receiver = invocation_receiver(outer);
        let redundant = receiver.is_some_and(|receiver| {
            receiver.kind() == "invocation_expression"
                && callee_name(receiver, source) == Some("GetType")
        });
        if redundant {
            issues.push(issue(
                language,
                "S3443",
                "Remove this redundant 'GetType' call; it already returns a System.Type.",
                range_of(outer),
            ));
        }
    }
    issues
}

/// Whether the body guards `parameter` against null explicitly.
fn null_guards_parameter(body: Node<'_>, parameter: &str, source: &str) -> bool {
    let comparison_guard = comparisons(body).iter().any(|(expression, left, right)| {
        matches!(operator_of(*expression), Some("==" | "!="))
            && [left, right]
                .iter()
                .any(|side| side.kind() == "identifier" && node_text(**side, source) == parameter)
            && [left, right]
                .iter()
                .any(|side| side.kind() == "null_literal")
    });
    comparison_guard
        || node_text(body, source).contains(&format!("{parameter} is null"))
        || node_text(body, source).contains(&format!("{parameter} is not null"))
        || collect_kinds(body, &["invocation_expression"])
            .iter()
            .any(|invocation| {
                callee_name(*invocation, source)
                    .is_some_and(|callee| callee.ends_with("ThrowIfNull"))
                    && invocation_arguments(*invocation)
                        .iter()
                        .any(|argument| expression_name(*argument, source) == Some(parameter))
            })
}

/// csharpsquid:S3900 — public methods validate annotated nullable
/// reference parameters before using them. Restricted to `?`-annotated
/// parameters so single-file analysis stays sound.
fn check_unvalidated_public_parameters(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) || !has_modifier(&modifiers_of(method, source), "public") {
            continue;
        }
        let Some(body) = body_of(method) else {
            continue;
        };
        for parameter in parameters_of(method) {
            if is_error_tainted(parameter)
                || modifiers_of(parameter, source)
                    .iter()
                    .any(|modifier| matches!(*modifier, "this"))
            {
                continue;
            }
            let Some(type_node) = parameter.child_by_field_name("type") else {
                continue;
            };
            if !node_text(type_node, source).trim().ends_with('?') {
                continue;
            }
            let Some(name_node) = parameter.child_by_field_name("name") else {
                continue;
            };
            let name = node_text(name_node, source);
            if null_guards_parameter(body, name, source) {
                continue;
            }
            let dereference = collect_kinds(body, &["identifier"])
                .into_iter()
                .find(|identifier| {
                    !is_error_tainted(*identifier)
                        && node_text(*identifier, source) == name
                        && identifier.parent().is_some_and(|parent| {
                            matches!(
                                parent.kind(),
                                "member_access_expression"
                                    | "element_access_expression"
                                    | "element_binding_expression"
                            ) && first_named_child(parent)
                                .is_some_and(|base| base.id() == identifier.id())
                                || (parent.kind() == "invocation_expression"
                                    && invocation_function(parent) == Some(*identifier))
                        })
                });
            if let Some(dereference) = dereference {
                issues.push(issue(
                    language,
                    "S3900",
                    format!("Validate parameter '{name}' against null before using it."),
                    range_of(dereference),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S3997 — string overloads beside Uri overloads delegate to
/// the Uri version instead of re-implementing it.
fn check_string_uri_overload_delegation(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut groups: std::collections::HashMap<&str, Vec<Node>> = std::collections::HashMap::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) {
            continue;
        }
        if let Some(name) = method.child_by_field_name("name") {
            groups
                .entry(node_text(name, source))
                .or_default()
                .push(method);
        }
    }
    let mut issues = Vec::new();
    for (name, methods) in groups {
        if methods.len() < 2 {
            continue;
        }
        let takes_uri = |method: Node| {
            parameters_of(method).iter().any(|parameter| {
                parameter
                    .child_by_field_name("type")
                    .is_some_and(|type_node| simple_name(node_text(type_node, source)) == "Uri")
            })
        };
        if !methods.iter().copied().any(takes_uri) {
            continue;
        }
        for method in methods {
            if takes_uri(method)
                || has_contract_modifier(&modifiers_of(method, source))
                || collect_kinds(method, &["object_creation_expression"])
                    .into_iter()
                    .any(|creation| {
                        creation
                            .child_by_field_name("type")
                            .is_some_and(|type_node| {
                                simple_name(node_text(type_node, source)) == "Uri"
                            })
                    })
            {
                continue;
            }
            issues.push(issue(
                language,
                "S3997",
                format!("Delegate this string-based '{name}' overload to the Uri overload."),
                range_of(name_anchor(method)),
            ));
        }
    }
    issues
}

/// csharpsquid:S4002 — finalizers on `IDisposable` types fight the dispose
/// pattern.
fn check_disposable_types_with_finalizers(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_node in collect_kinds(root, &["class_declaration"]) {
        if is_error_tainted(class_node)
            || !base_simple_names(class_node, source).contains(&"IDisposable")
        {
            continue;
        }
        for destructor in collect_kinds(class_node, &["destructor_declaration"]) {
            if is_error_tainted(destructor) {
                continue;
            }
            issues.push(issue(
                language,
                "S4002",
                "Remove this finalizer or implement the dispose pattern correctly.",
                range_of(name_anchor(destructor)),
            ));
        }
    }
    issues
}

/// csharpsquid:S4275 — accessors of one property must agree on the backing
/// field they touch.
fn check_accessor_backing_field_mismatch(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for property in collect_kinds(root, &["property_declaration"]) {
        if is_error_tainted(property) {
            continue;
        }
        let Some(property_name) = property.child_by_field_name("name") else {
            continue;
        };
        let mut getter_field_name: Option<&str> = None;
        let mut setter_field_name: Option<&str> = None;
        for accessor in accessors_of(property) {
            match accessor_keyword(accessor, source) {
                "get" => getter_field_name = getter_field(accessor, source),
                "set" => setter_field_name = setter_field(accessor, source),
                _ => {}
            }
        }
        match (getter_field_name, setter_field_name) {
            (Some(read), Some(written)) if read != written => issues.push(issue(
                language,
                "S4275",
                format!(
                    "'get' and 'set' accessors of '{}' touch different fields ('{read}' vs '{written}').",
                    node_text(property_name, source)
                ),
                range_of(property_name),
            )),
            _ => {}
        }
    }
    issues
}

// ======================================================================
// Tier B — needs intra-procedural dataflow / CFG (best effort)
//
// Every pass below approximates a path-sensitive analysis with
// statement-level reasoning and states its bound explicitly:
// straight-line sequences inside one block, unconditional statements
// only, and textual guard recognition. Passes prefer missing a finding
// over reporting a wrong one — genuine path sensitivity is out of scope
// here, so branch-dependent facts (a store dying on one path only, a
// lock released on the exceptional path alone) are never reported.
// ======================================================================

fn unary_operator(expression: Node<'_>) -> Option<&'static str> {
    let mut cursor = expression.walk();
    expression
        .children(&mut cursor)
        .find(|child| {
            !child.is_named() && matches!(child.kind(), "!" | "~" | "+" | "-" | "++" | "--")
        })
        .map(|token| token.kind())
}

/// How an identifier occurrence acts as a pure write, if it does at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteKind {
    /// `x = …` replaces the previous value outright.
    Store,
    /// `x++` / `--x` read the value and overwrite it in one step.
    Increment,
}

/// Whether this identifier occurrence is a pure write target: the left
/// side of a plain `=` assignment, a `++`/`--` operand, or a declared
/// name. Compound assignments (`+=`) read first and never classify
/// here; plain call arguments are reads, so `out`/`ref` writes simply
/// stay untracked (conservative by design).
fn identifier_write(node: Node<'_>) -> Option<WriteKind> {
    let parent = node.parent()?;
    match parent.kind() {
        "assignment_expression" => {
            let is_store = operator_of(parent) == Some("=")
                && parent
                    .child_by_field_name("left")
                    .is_some_and(|left| left.id() == node.id());
            is_store.then_some(WriteKind::Store)
        }
        "prefix_unary_expression" | "postfix_unary_expression" => {
            matches!(unary_operator(parent), Some("++" | "--")).then_some(WriteKind::Increment)
        }
        "variable_declarator" => {
            let is_name = parent
                .child_by_field_name("name")
                .is_some_and(|name| name.id() == node.id());
            is_name.then_some(WriteKind::Store)
        }
        _ => None,
    }
}

/// Names receiving a write anywhere in the subtree: assignment targets,
/// increment operands, and declared names alike.
fn written_names<'a>(node: Node<'_>, source: &'a str) -> std::collections::HashSet<&'a str> {
    let mut names = std::collections::HashSet::new();
    walk_all(node, &mut |current| {
        if current.kind() == "identifier" && identifier_write(current).is_some() {
            names.insert(node_text(current, source));
        }
    });
    names
}

/// Locals declared by this block's direct statements (initializers and
/// declarations without one alike); `const` locals cannot be rewritten.
fn block_declared_local_names(block: Node<'_>, source: &str) -> Vec<String> {
    let mut names = Vec::new();
    for statement in block_statements(block) {
        if statement.kind() != "local_declaration_statement"
            || has_modifier(&modifiers_of(statement, source), "const")
        {
            continue;
        }
        for declarator in collect_kinds(statement, &["variable_declarator"]) {
            if let Some(name) = declarator.child_by_field_name("name") {
                let text = node_text(name, source);
                if text != "_" {
                    names.push(text.to_owned());
                }
            }
        }
    }
    names
}

/// Bodies of callables that carry a block: methods, constructors,
/// destructors, operators, accessors, and local functions.
fn callable_blocks(root: Node<'_>) -> Vec<Node<'_>> {
    const CALLABLE_KINDS: [&str; 6] = [
        "method_declaration",
        "constructor_declaration",
        "destructor_declaration",
        "operator_declaration",
        "accessor_declaration",
        "local_function_statement",
    ];
    collect_kinds(root, &CALLABLE_KINDS)
        .into_iter()
        .filter_map(body_of)
        .collect()
}

/// Names read inside a lambda, anonymous method, or local function —
/// their lifetimes escape the enclosing block, so dead-store tracking
/// skips them entirely.
fn captured_names(body: Node<'_>, source: &str) -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();
    for closure in collect_kinds(body, &["lambda_expression", "anonymous_method_expression"]) {
        for identifier in collect_kinds(closure, &["identifier"]) {
            names.insert(node_text(identifier, source).to_owned());
        }
    }
    names
}

/// Consumes every pending store whose name this statement reads. Pure
/// write occurrences do not consume; `out`/`ref` positions do.
fn consume_reads<'t>(
    statement: Node<'t>,
    source: &str,
    tracked: &std::collections::HashSet<String>,
    pending: &mut Vec<(String, WriteKind, Node<'t>)>,
) {
    for identifier in collect_kinds(statement, &["identifier"]) {
        let name = node_text(identifier, source);
        if tracked.contains(name) && identifier_write(identifier).is_none() {
            pending.retain(|(pending_name, _, _)| pending_name != name);
        }
    }
}

/// Registers the unconditional stores of a declaration statement. A new
/// store displaces any pending store of the same name, marking the old
/// value's death — it reports at that moment.
fn register_declaration_stores<'t>(
    statement: Node<'t>,
    source: &str,
    tracked: &std::collections::HashSet<String>,
    pending: &mut Vec<(String, WriteKind, Node<'t>)>,
    issues: &mut Vec<Issue>,
    language: CsLanguage,
) {
    for declarator in collect_kinds(statement, &["variable_declarator"]) {
        let Some(name_node) = declarator.child_by_field_name("name") else {
            continue;
        };
        let name = node_text(name_node, source);
        if tracked.contains(name) && declarator_initializer(declarator, name_node).is_some() {
            displace_pending(pending, name, issues, language);
            pending.push((name.to_owned(), WriteKind::Store, declarator));
        }
    }
}

/// Registers the unconditional stores of one expression statement:
/// plain `=` assignments and `++`/`--` operands.
fn register_expression_stores<'t>(
    statement: Node<'t>,
    source: &str,
    tracked: &std::collections::HashSet<String>,
    pending: &mut Vec<(String, WriteKind, Node<'t>)>,
    issues: &mut Vec<Issue>,
    language: CsLanguage,
) {
    for identifier in collect_kinds(statement, &["identifier"]) {
        let Some(write) = identifier_write(identifier) else {
            continue;
        };
        let name = node_text(identifier, source);
        if tracked.contains(name) {
            displace_pending(pending, name, issues, language);
            pending.push((name.to_owned(), write, identifier));
        }
    }
}

/// Reports every pending store of `name` as dead (overwritten unread)
/// and drops them from the pending list.
fn displace_pending(
    pending: &mut Vec<(String, WriteKind, Node<'_>)>,
    name: &str,
    issues: &mut Vec<Issue>,
    language: CsLanguage,
) {
    let displaced: Vec<_> = pending
        .iter()
        .filter(|(pending_name, _, _)| pending_name == name)
        .map(|(_, kind, anchor)| (*kind, *anchor))
        .collect();
    pending.retain(|(pending_name, _, _)| pending_name != name);
    for (kind, anchor) in displaced {
        push_dead_store(issues, language, name, kind, anchor);
    }
}

/// Reports one dead store with the rule its write shape dictates.
fn push_dead_store(
    issues: &mut Vec<Issue>,
    language: CsLanguage,
    name: &str,
    kind: WriteKind,
    anchor: Node<'_>,
) {
    match kind {
        WriteKind::Increment => issues.push(issue(
            language,
            "S2123",
            format!("'{name}' is incremented but the new value is never used."),
            range_of(anchor),
        )),
        WriteKind::Store => issues.push(issue(
            language,
            "S1854",
            format!("Remove this useless assignment to local variable '{name}'."),
            range_of(anchor),
        )),
    }
}

/// csharpsquid:S1854 and csharpsquid:S2123 — dead stores and useless
/// increments. Straight-line per block: only direct
/// `local_declaration_statement` / `expression_statement` children
/// register stores, every other child contributes reads alone, so
/// branch-local writes can never mask a pending store.
fn check_dead_stores(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        let captured = captured_names(body, source);
        for block in collect_kinds(body, &["block"]) {
            let declared = block_declared_local_names(block, source);
            if declared.is_empty() {
                continue;
            }
            let tracked: std::collections::HashSet<String> = declared
                .iter()
                .filter(|name| !captured.contains(*name))
                .cloned()
                .collect();
            let mut pending: Vec<(String, WriteKind, Node<'_>)> = Vec::new();
            for statement in block_statements(block) {
                consume_reads(statement, source, &tracked, &mut pending);
                match statement.kind() {
                    "local_declaration_statement" => {
                        register_declaration_stores(
                            statement,
                            source,
                            &tracked,
                            &mut pending,
                            &mut issues,
                            language,
                        );
                    }
                    "expression_statement" => {
                        register_expression_stores(
                            statement,
                            source,
                            &tracked,
                            &mut pending,
                            &mut issues,
                            language,
                        );
                    }
                    _ => {}
                }
            }
            // Block scope ends: unread final values stay dead.
            for (name, kind, anchor) in pending {
                push_dead_store(&mut issues, language, &name, kind, anchor);
            }
        }
    }
    issues
}

/// csharpsquid:S127 — a `for` stop condition stays invariant: nothing in
/// the body may assign a name the condition tests. Update-clause writes
/// drive the loop and are exempt by design.
fn check_invariant_stop_conditions(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for for_statement in collect_kinds(root, &["for_statement"]) {
        if is_error_tainted(for_statement) {
            continue;
        }
        let Some(condition) = for_statement.child_by_field_name("condition") else {
            continue;
        };
        let condition_names: std::collections::HashSet<&str> =
            collect_kinds(condition, &["identifier"])
                .into_iter()
                .map(|identifier| node_text(identifier, source))
                .collect();
        let Some(body) = for_statement.child_by_field_name("body") else {
            continue;
        };
        let body_writes = written_names(body, source);
        if condition_names
            .iter()
            .any(|name| body_writes.contains(name))
        {
            issues.push(issue(
                language,
                "S127",
                "This loop's stop condition is not invariant.",
                range_of(for_statement),
            ));
        }
    }
    issues
}

/// Whether a loop body's final statement leaves the loop unconditionally.
fn trailing_statement_exits(body: Node<'_>) -> bool {
    let statements = if body.kind() == "block" {
        block_statements(body)
    } else {
        vec![body]
    };
    statements.last().is_some_and(|last| {
        matches!(
            last.kind(),
            "break_statement" | "return_statement" | "throw_statement"
        )
    })
}

/// Signed constant value of an integer literal, a `MinValue`/`MaxValue`
/// identifier, or a negation/parenthesization thereof.
fn constant_integer_value(expression: Node<'_>, source: &str) -> Option<i128> {
    match expression.kind() {
        "integer_literal" => integer_literal_value(node_text(expression, source))
            .and_then(|value| i64::try_from(value).ok())
            .map(i128::from),
        "parenthesized_expression" => {
            first_named_child(expression).and_then(|inner| constant_integer_value(inner, source))
        }
        "prefix_unary_expression" if unary_operator(expression) == Some("-") => {
            first_named_child(expression)
                .and_then(|operand| constant_integer_value(operand, source))
                .map(|value| -value)
        }
        // `int.MaxValue` parses as a member access, not an identifier,
        // so the known-constant table keys on text alone.
        _ => match node_text(expression, source) {
            "int.MinValue" | "Int32.MinValue" => Some(i128::from(i32::MIN)),
            "int.MaxValue" | "Int32.MaxValue" => Some(i128::from(i32::MAX)),
            "short.MinValue" => Some(i128::from(i16::MIN)),
            "short.MaxValue" => Some(i128::from(i16::MAX)),
            "long.MinValue" | "Int64.MinValue" => Some(i128::from(i64::MIN)),
            "long.MaxValue" | "Int64.MaxValue" => Some(i128::from(i64::MAX)),
            _ => None,
        },
    }
}

/// Whether a relational operator holds between two folded values.
fn relation_holds(left: i128, operator: &str, right: i128) -> bool {
    match operator {
        "<" => left < right,
        "<=" => left <= right,
        ">" => left > right,
        ">=" => left >= right,
        "==" => left == right,
        "!=" => left != right,
        _ => false,
    }
}

/// Entry value of a `for` counter: its initializer's integer literal.
fn counter_entry_value<'a>(loop_header: Node<'_>, source: &'a str) -> Option<(&'a str, i128)> {
    let (Some(initializer), _, _) = for_clauses(loop_header) else {
        return None;
    };
    let counter = counter_name(initializer, source)?;
    let literal = collect_kinds(initializer, &["integer_literal"])
        .into_iter()
        .next()?;
    let value = constant_integer_value(literal, source)?;
    Some((counter, value))
}

/// Entry-time falsity of a loop condition: a literal `false`, a
/// relational self-comparison (`x < x` is false for every value,
/// `NaN` included), or a `for` whose folded start/bound pair already
/// fails its own relation.
fn condition_false_at_entry(loop_header: Node<'_>, source: &str) -> bool {
    let Some(condition) = loop_header.child_by_field_name("condition") else {
        // `for (;;)` relies on escapes; the infinite-loop pass judges it.
        return false;
    };
    if condition.kind() == "boolean_literal" {
        return node_text(condition, source) == "false";
    }
    if condition.kind() != "binary_expression" {
        return false;
    }
    let operator = binary_operator(condition, source);
    let Some((left, right)) = binary_operands(condition) else {
        return false;
    };
    let left_text = node_text(left, source);
    let right_text = node_text(right, source);
    if matches!(operator, "<" | "<=" | ">" | ">=") && left_text == right_text {
        return true;
    }
    let (entry, bound) = match (
        constant_integer_value(left, source),
        constant_integer_value(right, source),
    ) {
        (Some(entry), Some(bound)) => (entry, bound),
        _ => match counter_entry_value(loop_header, source) {
            Some((counter, value)) if left_text == counter => {
                match constant_integer_value(right, source) {
                    Some(bound) => (value, bound),
                    None => return false,
                }
            }
            Some((counter, value)) if right_text == counter => {
                match constant_integer_value(left, source) {
                    Some(bound) => (bound, value),
                    None => return false,
                }
            }
            _ => return false,
        },
    };
    !relation_holds(entry, operator, bound)
}

/// csharpsquid:S1751 — loops that provably run at most once: the final
/// body statement leaves the loop unconditionally. Entry-false
/// conditions belong to S2252; `do`-while run-once idioms are exempt.
fn check_single_iteration_loops(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for header in collect_kinds(root, &["while_statement", "for_statement"]) {
        if is_error_tainted(header) {
            continue;
        }
        let Some(body) = header.child_by_field_name("body") else {
            continue;
        };
        if trailing_statement_exits(body) {
            issues.push(issue(
                language,
                "S1751",
                "This loop will execute at most once.",
                range_of(header),
            ));
        }
    }
    issues
}

/// csharpsquid:S2252 — a loop condition should hold at least once: a
/// condition that is already false at entry strands the body. `do`
/// bodies run before their condition and are exempt.
fn check_condition_true_at_least_once(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for header in collect_kinds(root, &["while_statement", "for_statement"]) {
        if is_error_tainted(header) {
            continue;
        }
        if condition_false_at_entry(header, source) {
            issues.push(issue(
                language,
                "S2252",
                "This loop's body never executes; the condition is false from the start.",
                range_of(header),
            ));
        }
    }
    issues
}

/// Direction a `for` update clause drives its counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CounterDirection {
    Increasing,
    Decreasing,
}

/// Direction of the first counter movement in an update clause:
/// `++`/`--`, `+=`/`-=`, or a re-assignment folding the counter with a
/// signed literal step.
fn update_direction(update: Node<'_>, counter: &str, source: &str) -> Option<CounterDirection> {
    for node in collect_kinds(
        update,
        &[
            "prefix_unary_expression",
            "postfix_unary_expression",
            "assignment_expression",
        ],
    ) {
        match node.kind() {
            "prefix_unary_expression" | "postfix_unary_expression" => {
                let touches_counter = first_named_child(node)
                    .is_some_and(|operand| node_text(operand, source) == counter);
                if touches_counter {
                    return match unary_operator(node) {
                        Some("++") => Some(CounterDirection::Increasing),
                        Some("--") => Some(CounterDirection::Decreasing),
                        _ => None,
                    };
                }
            }
            "assignment_expression" => {
                let Some(left) = node.child_by_field_name("left") else {
                    continue;
                };
                if node_text(left, source) != counter {
                    continue;
                }
                match operator_of(node) {
                    Some("+=") => return Some(CounterDirection::Increasing),
                    Some("-=") => return Some(CounterDirection::Decreasing),
                    Some("=") => {
                        let Some(right) = node.child_by_field_name("right") else {
                            continue;
                        };
                        if right.kind() == "binary_expression" {
                            let step = match binary_operator(right, source) {
                                "+" => CounterDirection::Increasing,
                                "-" => CounterDirection::Decreasing,
                                _ => continue,
                            };
                            let (lhs, rhs) = binary_operands(right)?;
                            let counter_side = [lhs, rhs]
                                .into_iter()
                                .any(|operand| node_text(operand, source) == counter);
                            if counter_side {
                                return Some(step);
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    None
}

/// csharpsquid:S2251 — a `for` counter must move toward its bound:
/// ascending against `<`/`<=`, or descending against `>`/`>=`, strands
/// the loop.
fn check_counter_direction(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for for_statement in collect_kinds(root, &["for_statement"]) {
        if is_error_tainted(for_statement) {
            continue;
        }
        let (initializer, condition, update) = for_clauses(for_statement);
        let (Some(initializer), Some(condition), Some(update)) = (initializer, condition, update)
        else {
            continue;
        };
        let Some(counter) = counter_name(initializer, source) else {
            continue;
        };
        let Some(direction) = update_direction(update, counter, source) else {
            continue;
        };
        let operator = binary_operator(condition, source);
        let references_counter = collect_kinds(condition, &["identifier"])
            .into_iter()
            .any(|identifier| node_text(identifier, source) == counter);
        let strands = references_counter
            && matches!(
                (operator, direction),
                ("<" | "<=", CounterDirection::Decreasing)
                    | (">" | ">=", CounterDirection::Increasing)
            );
        if strands {
            issues.push(issue(
                language,
                "S2251",
                format!("The counter '{counter}' moves away from this loop's bound."),
                range_of(for_statement),
            ));
        }
    }
    issues
}

/// Whether the loop condition is provably true at entry (literal `true`
/// or an omitted `for` condition).
fn condition_true_at_entry(header: Node<'_>, source: &str) -> bool {
    match header.child_by_field_name("condition") {
        None => header.kind() == "for_statement",
        Some(condition) => {
            condition.kind() == "boolean_literal" && node_text(condition, source) == "true"
        }
    }
}

/// Whether a subtree offers any way out: `break`, `return`, `throw`, or
/// an outward `goto`.
fn subtree_escapes(node: Node<'_>) -> bool {
    collect_kinds(
        node,
        &[
            "break_statement",
            "return_statement",
            "throw_statement",
            "goto_statement",
        ],
    )
    .iter()
    .any(|escape| !is_error_tainted(*escape))
}

/// csharpsquid:S2190 — loops whose entry-true condition has no escape in
/// the body never terminate. Tail self-recursion with no conditional
/// wrapper recurses forever the same way.
fn check_infinite_loops(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for header in collect_kinds(root, &["while_statement", "for_statement", "do_statement"]) {
        if is_error_tainted(header) || !condition_true_at_entry(header, source) {
            continue;
        }
        let Some(body) = header.child_by_field_name("body") else {
            continue;
        };
        if !subtree_escapes(body) {
            issues.push(issue(
                language,
                "S2190",
                "Add an escape from this loop; it never terminates.",
                range_of(header),
            ));
        }
    }
    for method in collect_kinds(root, &["method_declaration"]) {
        let Some(body) = body_of(method) else {
            continue;
        };
        let Some(name) = method.child_by_field_name("name") else {
            continue;
        };
        let own_name = node_text(name, source);
        let statements = block_statements(body);
        let Some(last) = statements.last().copied() else {
            continue;
        };
        let tail_call = match last.kind() {
            "expression_statement" | "return_statement" => first_named_child(last),
            _ => None,
        }
        .filter(|expression| expression.kind() == "invocation_expression")
        .filter(|call| callee_name(*call, source) == Some(own_name))
        .filter(|call| {
            invocation_receiver(*call).is_none_or(|receiver| {
                receiver.kind() == "identifier" && node_text(receiver, source) == "this"
            })
        });
        // A base case anywhere else in the body terminates the recursion
        // (`if (n <= 1) return 1; return Fact(n - 1);`): every escape
        // site must live inside the trailing call itself.
        let unguarded_tail = tail_call.is_some()
            && collect_kinds(body, &["return_statement", "throw_statement"])
                .into_iter()
                .all(|site| {
                    site.start_byte() >= last.start_byte() && site.end_byte() <= last.end_byte()
                });
        if unguarded_tail {
            issues.push(issue(
                language,
                "S2190",
                "Add a termination condition to this recursion.",
                range_of(last),
            ));
        }
    }
    issues
}

/// Pre-order walk that does not descend into `block` nodes; used when
/// the enclosing statement list already visits those blocks separately.
fn walk_except_blocks<'t>(node: Node<'t>, visit: &mut impl FnMut(Node<'t>)) {
    visit(node);
    if node.kind() == "block" {
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_except_blocks(child, visit);
    }
}

/// Methods that execute a command's SQL text directly.
const SQL_EXECUTE_METHODS: [&str; 4] = [
    "ExecuteReader",
    "ExecuteNonQuery",
    "ExecuteScalar",
    "ExecuteXmlReader",
];

/// Command types whose constructor takes the SQL text as first argument.
const SQL_COMMAND_TYPES: [&str; 6] = [
    "SqlCommand",
    "OleDbCommand",
    "OdbcCommand",
    "MySqlCommand",
    "SqliteCommand",
    "NpgsqlCommand",
];

/// Whether an expression builds its text from non-literal parts:
/// string interpolation, a concatenation with such a part, or an
/// identifier that is not a provably literal-only local. Unknown
/// provenance (parameters, fields) counts as dynamic — the rule is
/// deliberately one-sided.
fn is_dynamic_sql_text(
    expression: Node<'_>,
    source: &str,
    tainted: &std::collections::HashSet<String>,
    clean: &std::collections::HashSet<String>,
) -> bool {
    match expression.kind() {
        "string_literal" => false,
        "interpolated_string_expression" => collect_kinds(expression, &["interpolation"])
            .iter()
            .any(|part| !is_error_tainted(*part)),
        "binary_expression" if operator_of(expression) == Some("+") => binary_operands(expression)
            .is_some_and(|(left, right)| {
                is_dynamic_sql_text(left, source, tainted, clean)
                    || is_dynamic_sql_text(right, source, tainted, clean)
            }),
        // `invocation_arguments` yields `argument` wrappers around the
        // actual expressions; unwrap them here.
        "argument" => first_named_child(expression)
            .is_some_and(|inner| is_dynamic_sql_text(inner, source, tainted, clean)),
        "identifier" => {
            let name = node_text(expression, source);
            tainted.contains(name) || !clean.contains(name)
        }
        _ => true,
    }
}

/// Reports SQL-executing sites inside one statement whose command text
/// is dynamic: execute calls and command constructors with a tainted or
/// interpolated first argument, plus dynamic `CommandText` assignments.
fn scan_sql_usages<'t>(
    statement: Node<'t>,
    source: &str,
    language: CsLanguage,
    tainted: &std::collections::HashSet<String>,
    clean: &std::collections::HashSet<String>,
    issues: &mut Vec<Issue>,
) {
    let mut report = |anchor: Node<'t>| {
        issues.push(issue(
            language,
            "S2077",
            "Use a parameterized query or stored procedure for this SQL statement.",
            range_of(anchor),
        ));
    };
    walk_except_blocks(statement, &mut |node| match node.kind() {
        "invocation_expression" => {
            let dynamic = invocation_arguments(node)
                .first()
                .is_some_and(|argument| is_dynamic_sql_text(*argument, source, tainted, clean));
            if dynamic && SQL_EXECUTE_METHODS.contains(&callee_name(node, source).unwrap_or("")) {
                report(node);
            }
        }
        "object_creation_expression" => {
            let type_name = node
                .child_by_field_name("type")
                .map_or("", |type_node| simple_name(node_text(type_node, source)));
            let dynamic = invocation_arguments(node)
                .first()
                .is_some_and(|argument| is_dynamic_sql_text(*argument, source, tainted, clean));
            if dynamic && SQL_COMMAND_TYPES.contains(&type_name) {
                report(node);
            }
        }
        "assignment_expression" => {
            let targets_command_text = operator_of(node) == Some("=")
                && node.child_by_field_name("left").is_some_and(|left| {
                    expression_name(left, source) == Some("CommandText")
                        && left.kind() == "member_access_expression"
                });
            let dynamic = node
                .child_by_field_name("right")
                .is_some_and(|right| is_dynamic_sql_text(right, source, tainted, clean));
            if targets_command_text && dynamic {
                report(node);
            }
        }
        _ => {}
    });
}

/// Updates the per-block taint sets with one statement's stores: a
/// store of dynamic text taints the name; any other store marks it
/// provably literal-only.
fn update_sql_taint(
    statement: Node<'_>,
    source: &str,
    tainted: &mut std::collections::HashSet<String>,
    clean: &mut std::collections::HashSet<String>,
) {
    for identifier in collect_kinds(statement, &["identifier"]) {
        let Some(write) = identifier_write(identifier) else {
            continue;
        };
        let name = node_text(identifier, source).to_owned();
        let stores_dynamic = match write {
            WriteKind::Increment => false,
            WriteKind::Store => identifier.parent().is_some_and(|parent| {
                parent
                    .child_by_field_name("right")
                    .is_some_and(|right| is_dynamic_sql_text(right, source, tainted, clean))
                    || declarator_initializer(parent, identifier)
                        .is_some_and(|value| is_dynamic_sql_text(value, source, tainted, clean))
            }),
        };
        if stores_dynamic {
            tainted.insert(name.clone());
            clean.remove(&name);
        } else {
            clean.insert(name.clone());
            tainted.remove(&name);
        }
    }
}

/// csharpsquid:S2077 — dynamically formatted SQL invites injection.
/// Bound: straight-line taint inside each block — locals composed by
/// interpolation or concatenation flow into execute calls, command
/// constructors, and `CommandText` assignments. Taint through fields,
/// parameters, or across branches counts as dynamic on arrival.
fn check_dynamic_sql(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        for block in collect_kinds(body, &["block"]) {
            let mut tainted = std::collections::HashSet::new();
            let mut clean = std::collections::HashSet::new();
            for statement in block_statements(block) {
                scan_sql_usages(statement, source, language, &tainted, &clean, &mut issues);
                update_sql_taint(statement, source, &mut tainted, &mut clean);
            }
        }
    }
    issues
}

/// `Monitor.Enter`/`TryEnter`/`Exit` invocations paired with their lock
/// object text, in document order.
fn monitor_operations<'a, 't>(
    body: Node<'t>,
    source: &'a str,
) -> Vec<(&'a str, &'a str, Node<'t>)> {
    collect_kinds(body, &["invocation_expression"])
        .into_iter()
        .filter_map(|call| {
            let method = callee_name(call, source)?;
            matches!(method, "Enter" | "TryEnter" | "Exit").then_some(())?;
            let receiver = invocation_receiver(call)?;
            (node_text(receiver, source) == "Monitor").then_some(())?;
            // Reader/writer releases take no argument, so prefer the
            // receiver as the pairing key and fall back to the argument.
            let key = invocation_receiver(call)
                .map(|receiver| node_text(receiver, source))
                .or_else(|| {
                    invocation_arguments(call)
                        .into_iter()
                        .next()
                        .map(|argument| node_text(argument, source))
                })?;
            Some((method, key, call))
        })
        .collect()
}

/// csharpsquid:S2222 — every `Monitor.Enter` needs its `Exit` on all
/// paths: an exit that is not wrapped in a `finally` leaves the lock
/// held when exceptions unwind. Bound: pairing resolved within one
/// member body, by lock-object text.
fn check_monitor_release_paths(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        let operations = monitor_operations(body, source);
        for (index, (method, object, enter)) in operations.iter().enumerate() {
            if *method == "Exit" {
                continue;
            }
            let later_exits = operations[index + 1..]
                .iter()
                .filter(|(exit_method, exit_object, exit_call)| {
                    *exit_method == "Exit"
                        && exit_object == object
                        && exit_call.start_byte() > enter.end_byte()
                })
                .collect::<Vec<_>>();
            let released_on_all_paths = later_exits.is_empty()
                || later_exits.iter().any(|(_, _, exit_call)| {
                    has_ancestor_with_kind(*exit_call, &["finally_clause"])
                });
            if released_on_all_paths {
                continue;
            }
            issues.push(issue(
                language,
                "S2222",
                "Release this lock on every path through the code.",
                range_of(*enter),
            ));
        }
    }
    issues
}

/// Ancestors between `node` and its nearest block-like boundary that run
/// conditionally: branches, loops, handlers, short-circuit operands.
fn conditional_context(node: Node<'_>) -> bool {
    ancestors_of(node)
        .take_while(|ancestor| {
            !matches!(
                ancestor.kind(),
                "method_declaration"
                    | "constructor_declaration"
                    | "destructor_declaration"
                    | "accessor_declaration"
                    | "local_function_statement"
                    | "operator_declaration"
            )
        })
        .any(|ancestor| {
            matches!(
                ancestor.kind(),
                "if_statement"
                    | "while_statement"
                    | "for_statement"
                    | "foreach_statement"
                    | "do_statement"
                    | "switch_statement"
                    | "switch_section"
                    | "try_statement"
                    | "catch_clause"
                    | "finally_clause"
                    | "conditional_expression"
                    | "using_statement"
            )
        })
}

/// Whether the member body guards `name` somewhere: a `HasValue` check,
/// an explicit null comparison, an `is not null` pattern, or a
/// null-conditional access. Guarded names are exempt entirely.
fn name_is_guarded(body_text: &str, name: &str) -> bool {
    [
        "{name}.HasValue",
        "{name} != null",
        "{name} is not null",
        "{name}?.",
    ]
    .iter()
    .any(|pattern| body_text.contains(pattern.replace("{name}", name).as_str()))
}

/// csharpsquid:S2259 — dereferencing a known-null reference crashes.
/// Bound: straight-line knowledge inside one block — names assigned
/// `null` by an unconditional statement stay null until another store
/// or an unknown-state use (`out`/`ref`) clears them; a member-wide
/// textual guard exempts a name entirely. Cross-branch reasoning is out
/// of scope.
fn check_null_dereferences(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        let body_text = node_text(body, source);
        for block in collect_kinds(body, &["block"]) {
            let mut known_null: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            for statement in block_statements(block) {
                // Dereferences first: statements are processed in order.
                walk_except_blocks(statement, &mut |node| {
                    if !matches!(
                        node.kind(),
                        "member_access_expression" | "element_access_expression"
                    ) {
                        return;
                    }
                    let Some(base) = node.child_by_field_name("expression") else {
                        return;
                    };
                    if base.kind() != "identifier" {
                        return;
                    }
                    let name = node_text(base, source);
                    if !known_null.contains(name)
                        || node_text(node, source).contains('?')
                        || name_is_guarded(body_text, name)
                    {
                        return;
                    }
                    issues.push(issue(
                        language,
                        "S2259",
                        format!("'{name}' is null here; this dereference will throw."),
                        range_of(base),
                    ));
                });
                // Then state updates from this statement's writes.
                for identifier in collect_kinds(statement, &["identifier"]) {
                    let passes_by_reference = identifier.parent().is_some_and(|parent| {
                        parent.kind() == "argument"
                            && parent.children(&mut parent.walk()).any(|child| {
                                !child.is_named()
                                    && matches!(node_text(child, source), "out" | "ref")
                            })
                    });
                    if passes_by_reference {
                        known_null.remove(node_text(identifier, source));
                        continue;
                    }
                    match identifier_write(identifier) {
                        Some(WriteKind::Store) => {
                            let stores_null = identifier.parent().is_some_and(|parent| {
                                parent
                                    .child_by_field_name("right")
                                    .is_some_and(|right| right.kind() == "null_literal")
                                    || declarator_initializer(parent, identifier)
                                        .is_some_and(|value| value.kind() == "null_literal")
                            });
                            if stores_null && !conditional_context(identifier) {
                                known_null.insert(node_text(identifier, source).to_owned());
                            } else {
                                known_null.remove(node_text(identifier, source));
                            }
                        }
                        Some(WriteKind::Increment) => {
                            known_null.remove(node_text(identifier, source));
                        }
                        None => {}
                    }
                }
            }
        }
    }
    issues
}

/// csharpsquid:S2583 — a condition that is literally `false` guards code
/// that can never run.
fn check_always_false_conditions(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for header in collect_kinds(
        root,
        &[
            "if_statement",
            "while_statement",
            "for_statement",
            "conditional_expression",
        ],
    ) {
        if is_error_tainted(header) {
            continue;
        }
        let Some(condition) = header.child_by_field_name("condition") else {
            continue;
        };
        if condition.kind() == "boolean_literal" && node_text(condition, source) == "false" {
            issues.push(issue(
                language,
                "S2583",
                "This condition is always false; the guarded code never runs.",
                range_of(condition),
            ));
        }
    }
    issues
}

/// csharpsquid:S2589 — boolean literals next to a short-circuit operator
/// change nothing about the result. Comparisons against literals and
/// doubled negations are covered by S1125 and S2761 instead.
fn check_gratuitous_boolean_operands(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(expression) || !matches!(operator_of(expression), Some("&&" | "||")) {
            continue;
        }
        let Some((left, right)) = binary_operands(expression) else {
            continue;
        };
        for operand in [left, right] {
            if operand.kind() == "boolean_literal" {
                issues.push(issue(
                    language,
                    "S2589",
                    "This boolean literal is gratuitous in a short-circuit operation.",
                    range_of(operand),
                ));
            }
        }
    }
    issues
}

/// Stream reads whose returned length matters.
const STREAM_READ_METHODS: [&str; 3] = ["Read", "ReadBlock", "ReadAsync"];

/// csharpsquid:S2674 — a stream read's return value says how many bytes
/// landed; discarding it invites stale-buffer bugs. Bound: only fully
/// discarded results are flagged — comparing the count correctly needs
/// value-flow this pass does not model.
fn check_stream_reads_unchecked(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["expression_statement"])
        .into_iter()
        .filter(|statement| !is_error_tainted(*statement))
        .filter_map(|statement| first_named_child(statement))
        .filter(|expression| {
            expression.kind() == "invocation_expression"
                && STREAM_READ_METHODS.contains(&callee_name(*expression, source).unwrap_or(""))
        })
        .map(|call| {
            issue(
                language,
                "S2674",
                "Check the value returned by this stream read.",
                range_of(call),
            )
        })
        .collect()
}

/// Primitive types a `const` local may declare.
const CONST_CANDIDATE_TYPES: [&str; 14] = [
    "bool", "byte", "char", "decimal", "double", "float", "int", "long", "sbyte", "short",
    "string", "uint", "ulong", "ushort",
];

/// csharpsquid:S3353 — locals declared once from a literal and never
/// rewritten carry `const`. Bound: writes counted across the whole
/// member body; lambda-captured names stay exempt because capture
/// freezes their lifetime to the closure instead.
fn check_const_local_candidates(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        let captured = captured_names(body, source);
        let mut write_counts: std::collections::HashMap<&str, u32> =
            std::collections::HashMap::new();
        for identifier in collect_kinds(body, &["identifier"]) {
            if identifier_write(identifier).is_some() {
                *write_counts
                    .entry(node_text(identifier, source))
                    .or_default() += 1;
            }
        }
        for declaration in collect_kinds(body, &["local_declaration_statement"]) {
            if has_modifier(&modifiers_of(declaration, source), "const") {
                continue;
            }
            let type_text = declaration
                .children(&mut declaration.walk())
                .find(|child| child.kind() == "variable_declaration")
                .and_then(|variable| variable.child_by_field_name("type"))
                .map_or("", |type_node| simple_name(node_text(type_node, source)));
            if !CONST_CANDIDATE_TYPES.contains(&type_text) {
                continue;
            }
            for declarator in collect_kinds(declaration, &["variable_declarator"]) {
                let Some(name) = declarator.child_by_field_name("name") else {
                    continue;
                };
                let name = node_text(name, source);
                let literal_initializer = declarator_initializer(
                    declarator,
                    declarator.child_by_field_name("name").unwrap_or(declarator),
                )
                .is_some_and(|value| {
                    matches!(
                        value.kind(),
                        "integer_literal"
                            | "real_literal"
                            | "string_literal"
                            | "character_literal"
                            | "boolean_literal"
                    )
                });
                if literal_initializer
                    && !captured.contains(name)
                    && write_counts.get(name).copied().unwrap_or(0) <= 1
                {
                    issues.push(issue(
                        language,
                        "S3353",
                        format!("Declare '{name}' as 'const'."),
                        range_of(declarator),
                    ));
                }
            }
        }
    }
    issues
}

/// Whether an expression computes a value without observable effects.
fn side_effect_free(expression: Node<'_>) -> bool {
    collect_kinds(
        expression,
        &[
            "invocation_expression",
            "object_creation_expression",
            "assignment_expression",
            "prefix_unary_expression",
            "postfix_unary_expression",
            "await_expression",
        ],
    )
    .is_empty()
}

/// csharpsquid:S3440 — comparing a variable with the very value it just
/// received cannot vary. Bound: consecutive statements within one block;
/// the assigned expression must be side-effect free so its two textual
/// appearances denote one value.
fn check_compare_after_assignment(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    const CONDITION_KINDS: [&str; 4] = [
        "if_statement",
        "while_statement",
        "do_statement",
        "switch_statement",
    ];
    let mut issues = Vec::new();
    for block in collect_kinds(root, &["block"]) {
        let statements = block_statements(block);
        for window in statements.windows(2) {
            let (first, second) = (window[0], window[1]);
            if first.kind() != "expression_statement" || !CONDITION_KINDS.contains(&second.kind()) {
                continue;
            }
            let Some(assignment) = first_named_child(first) else {
                continue;
            };
            if assignment.kind() != "assignment_expression" || operator_of(assignment) != Some("=")
            {
                continue;
            }
            let Some((target, value)) = binary_operands(assignment) else {
                continue;
            };
            if target.kind() != "identifier" || !side_effect_free(value) {
                continue;
            }
            let target_name = node_text(target, source);
            let value_text = node_text(value, source);
            let condition = second
                .child_by_field_name("condition")
                .or_else(|| second.child_by_field_name("value"));
            let Some(condition) = condition else { continue };
            for comparison in collect_kinds(condition, &["binary_expression"]) {
                let matches_pair = binary_operands(comparison).is_some_and(|(left, right)| {
                    (node_text(left, source) == target_name
                        && node_text(right, source) == value_text)
                        || (node_text(left, source) == value_text
                            && node_text(right, source) == target_name)
                });
                if matches_pair
                    && matches!(
                        operator_of(comparison),
                        Some("==" | "!=" | "<" | "<=" | ">" | ">=")
                    )
                {
                    issues.push(issue(
                        language,
                        "S3440",
                        format!("'{target_name}' was just assigned this exact value; this comparison cannot vary."),
                        range_of(comparison),
                    ));
                }
            }
        }
    }
    issues
}

/// csharpsquid:S3655 — reading `.Value` of a nullable without checking
/// `HasValue` throws when the value is absent. Bound: nullable-typed
/// parameters and locals of the enclosing callable; any member-wide
/// guard (`HasValue`, null comparison, `is not null`, `?.`) exempts the
/// name.
fn check_nullable_value_access(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for declaration in callable_declarations(root) {
        let Some(body) = body_of(declaration) else {
            continue;
        };
        let mut nullable_names = std::collections::HashSet::new();
        for parameter in parameters_of(declaration) {
            if parameter_ends_nullable(parameter, source)
                && let Some(name) = parameter.child_by_field_name("name")
            {
                nullable_names.insert(node_text(name, source).to_owned());
            }
        }
        for variable in collect_kinds(body, &["variable_declaration"]) {
            let nullable = variable
                .child_by_field_name("type")
                .is_some_and(|type_node| node_text(type_node, source).ends_with('?'));
            if !nullable {
                continue;
            }
            for declarator in collect_kinds(variable, &["variable_declarator"]) {
                if let Some(name) = declarator.child_by_field_name("name") {
                    nullable_names.insert(node_text(name, source).to_owned());
                }
            }
        }
        if nullable_names.is_empty() {
            continue;
        }
        let body_text = node_text(body, source);
        for access in collect_kinds(body, &["member_access_expression"]) {
            let Some(member) = access.child_by_field_name("name") else {
                continue;
            };
            if node_text(member, source) != "Value" {
                continue;
            }
            let Some(base) = access.child_by_field_name("expression") else {
                continue;
            };
            if base.kind() != "identifier" {
                continue;
            }
            let name = node_text(base, source);
            if nullable_names.contains(name) && !name_is_guarded(body_text, name) {
                issues.push(issue(
                    language,
                    "S3655",
                    format!("Check 'HasValue' before accessing '{name}.Value'."),
                    range_of(access),
                ));
            }
        }
    }
    issues
}

/// Callables whose parameters and locals the nullable checks consider.
const CALLABLE_DECLARATION_KINDS: [&str; 7] = [
    "method_declaration",
    "constructor_declaration",
    "destructor_declaration",
    "operator_declaration",
    "accessor_declaration",
    "local_function_statement",
    "property_declaration",
];

fn callable_declarations(root: Node<'_>) -> Vec<Node<'_>> {
    collect_kinds(root, &CALLABLE_DECLARATION_KINDS)
}

fn parameter_ends_nullable(parameter: Node<'_>, source: &str) -> bool {
    parameter
        .child_by_field_name("type")
        .is_some_and(|type_node| node_text(type_node, source).ends_with('?'))
}

/// csharpsquid:S3949 — arithmetic on folded operands that wraps around
/// `int` silently corrupts the result; `checked` blocks are exempt by
/// intent. Bound: both operands must fold to constants within `int`
/// range (`int.MinValue`/`int.MaxValue` included).
fn check_overflow_prone_calculations(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(expression)
            || has_ancestor_with_kind(expression, &["checked_statement"])
        {
            continue;
        }
        let Some(operator) = operator_of(expression) else {
            continue;
        };
        if !matches!(operator, "+" | "-" | "*") {
            continue;
        }
        let Some((left, right)) = binary_operands(expression) else {
            continue;
        };
        let (Some(lhs), Some(rhs)) = (
            constant_integer_value(left, source),
            constant_integer_value(right, source),
        ) else {
            continue;
        };
        let Ok(lhs) = i32::try_from(lhs) else {
            continue;
        };
        let Ok(rhs) = i32::try_from(rhs) else {
            continue;
        };
        let wrapped = match operator {
            "+" => lhs.wrapping_add(rhs),
            "-" => lhs.wrapping_sub(rhs),
            _ => lhs.wrapping_mul(rhs),
        };
        let mathematical = match operator {
            "+" => i128::from(lhs) + i128::from(rhs),
            "-" => i128::from(lhs) - i128::from(rhs),
            _ => i128::from(lhs) * i128::from(rhs),
        };
        if i128::from(wrapped) != mathematical {
            issues.push(issue(
                language,
                "S3949",
                "This calculation overflows the range of 'int'; widen the operands or use a 'checked' block.",
                range_of(expression),
            ));
        }
    }
    issues
}

/// csharpsquid:S3966 — disposing an object twice either throws or hides
/// a lifecycle bug. Bound: document order across the member body —
/// branches that each dispose the same object are indistinguishable, so
/// a second dispose after an intervening store is clean but two bare
/// disposes are not. The enclosing `using` counts as a dispose too.
fn check_double_dispose(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        let mut disposed: std::collections::HashSet<String> = std::collections::HashSet::new();
        walk_all(body, &mut |node| match node.kind() {
            "invocation_expression" => {
                if callee_name(node, source) != Some("Dispose") {
                    return;
                }
                let Some(receiver) = invocation_receiver(node) else {
                    return;
                };
                let name = expression_name(receiver, source).unwrap_or("");
                let under_using = nearest_ancestor_of_kinds(node, &["using_statement"])
                    .is_some_and(|using| {
                        collect_kinds(using, &["variable_declarator"])
                            .iter()
                            .any(|declarator| {
                                declarator
                                    .child_by_field_name("name")
                                    .is_some_and(|declared| node_text(declared, source) == name)
                            })
                    });
                if under_using || disposed.contains(name) {
                    issues.push(issue(
                        language,
                        "S3966",
                        format!("'{name}' is disposed more than once."),
                        range_of(node),
                    ));
                } else {
                    disposed.insert(name.to_owned());
                }
            }
            "identifier" if identifier_write(node) == Some(WriteKind::Store) => {
                disposed.remove(node_text(node, source));
            }
            _ => {}
        });
    }
    issues
}

/// Collection types a zero-argument construction yields empty.
const EMPTY_ACCESS_COLLECTION_TYPES: [&str; 9] = [
    "List",
    "Dictionary",
    "HashSet",
    "SortedSet",
    "SortedList",
    "SortedDictionary",
    "Queue",
    "Stack",
    "LinkedList",
];

/// Whether this creation provably produces an empty collection:
/// a zero-length array, an empty `{}` initializer, or a known
/// collection type constructed without arguments.
fn is_empty_collection_creation(node: Node<'_>, source: &str) -> bool {
    match node.kind() {
        "array_creation_expression" => {
            let ranks = collect_kinds(node, &["array_rank_specifier"]);
            !ranks.is_empty()
                && ranks.iter().all(|rank| {
                    let sizes = collect_kinds(*rank, &["integer_literal"]);
                    sizes.is_empty() || sizes.iter().all(|size| node_text(*size, source) == "0")
                })
        }
        "implicit_array_creation_expression" => {
            let initializer = collect_kinds(node, &["initializer_expression"]);
            initializer.iter().all(|init| {
                !init
                    .children(&mut init.walk())
                    .any(|child| child.is_named())
            })
        }
        "object_creation_expression" => {
            let type_name = node
                .child_by_field_name("type")
                .map_or("", |type_node| simple_name(node_text(type_node, source)));
            EMPTY_ACCESS_COLLECTION_TYPES.contains(&type_name)
                && invocation_arguments(node).is_empty()
        }
        _ => false,
    }
}

/// csharpsquid:S4158 — indexing or iterating an empty collection fails
/// at runtime. Bound: direct chains off a provably empty creation
/// (indexing, `MoveNext`, `foreach`); values stored into variables lose
/// their provenance on purpose.
fn check_empty_collection_access(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for creation in collect_kinds(
        root,
        &[
            "array_creation_expression",
            "implicit_array_creation_expression",
            "object_creation_expression",
        ],
    ) {
        if is_error_tainted(creation) || !is_empty_collection_creation(creation, source) {
            continue;
        }
        let mut current = Some(creation);
        while let Some(node) = current {
            current = node.parent();
            match node.parent().map(|parent| parent.kind()) {
                Some("parenthesized_expression") => {}
                Some("element_access_expression" | "foreach_statement") => {
                    issues.push(issue(
                        language,
                        "S4158",
                        "This collection is created empty; accessing its elements will fail at runtime.",
                        range_of(creation),
                    ));
                    break;
                }
                Some("invocation_expression") => {
                    if node
                        .parent()
                        .is_some_and(|parent| callee_name(parent, source) == Some("MoveNext"))
                    {
                        issues.push(issue(
                            language,
                            "S4158",
                            "This collection is created empty; accessing its elements will fail at runtime.",
                            range_of(creation),
                        ));
                        break;
                    }
                    break;
                }
                _ => break,
            }
        }
    }
    issues
}

/// Gathers every Tier-B intra-procedural dataflow/CFG issue.
fn dataflow_cfg_issues(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_invariant_stop_conditions(root, source, language));
    issues.extend(check_single_iteration_loops(root, language));
    issues.extend(check_condition_true_at_least_once(root, source, language));
    issues.extend(check_dead_stores(root, source, language));
    issues.extend(check_dynamic_sql(root, source, language));
    issues.extend(check_infinite_loops(root, source, language));
    issues.extend(check_monitor_release_paths(root, source, language));
    issues.extend(check_counter_direction(root, source, language));
    issues.extend(check_null_dereferences(root, source, language));
    issues.extend(check_always_false_conditions(root, source, language));
    issues.extend(check_gratuitous_boolean_operands(root, language));
    issues.extend(check_stream_reads_unchecked(root, source, language));
    issues.extend(check_const_local_candidates(root, source, language));
    issues.extend(check_compare_after_assignment(root, source, language));
    issues.extend(check_nullable_value_access(root, source, language));
    issues.extend(check_overflow_prone_calculations(root, source, language));
    issues.extend(check_double_dispose(root, source, language));
    issues.extend(check_empty_collection_access(root, source, language));
    issues
}

// ======================================================================
// Tier B — needs framework/API pattern matching with small dataflow
//
// These rules match known .NET API shapes and follow values one or two
// statements at most. Each detector documents its bound; anything that
// needs a real type system (overload resolution, inheritance-wide
// search) is approximated by name and flagged conservatively.
// ======================================================================

/// Expressions of every attribute argument directly attached to a node
/// (`[Export(typeof(I))]` yields `typeof(I)`).
fn attribute_argument_texts<'a>(node: Node<'_>, source: &'a str) -> Vec<&'a str> {
    let mut texts = Vec::new();
    for attribute in collect_kinds(node, &["attribute"]) {
        for argument in collect_kinds(attribute, &["attribute_argument"]) {
            if let Some(value) = argument
                .children(&mut argument.walk())
                .find(tree_sitter::Node::is_named)
            {
                texts.push(node_text(value, source));
            }
        }
    }
    texts
}

/// The contract type of a `typeof(T)` argument, if one is present.
fn simple_name_of_typeof(argument_text: &str) -> Option<String> {
    let trimmed = argument_text.trim();
    let inner = trimmed
        .strip_prefix("typeof(")
        .and_then(|rest| rest.strip_suffix(')'))?
        .trim();
    inner.rsplit('.').next().map(str::to_owned)
}

/// `HttpCookie` creations paired with the local or property they are
/// stored in; unbound creations (`new HttpCookie(..)` as an argument)
/// are skipped.
fn cookie_creations<'t, 's>(body: Node<'t>, source: &'s str) -> Vec<(Node<'t>, &'s str)> {
    collect_kinds(body, &["object_creation_expression"])
        .into_iter()
        .filter(|creation| {
            creation
                .child_by_field_name("type")
                .map(|type_node| simple_name(node_text(type_node, source)))
                == Some("HttpCookie")
        })
        .filter_map(|creation| {
            let parent = creation.parent()?;
            let bound = match parent.kind() {
                "variable_declarator" => parent.child_by_field_name("name"),
                "assignment_expression" => parent.child_by_field_name("left"),
                _ => None,
            };
            let name = bound.and_then(|bound| assignment_target_name(bound, source))?;
            Some((creation, name))
        })
        .collect()
}

/// Whether the member sets `<name>.<property> = true` anywhere.
fn cookie_sets_property_true(body: Node<'_>, source: &str, name: &str, property: &str) -> bool {
    collect_kinds(body, &["assignment_expression"])
        .into_iter()
        .any(|assignment| {
            operator_of(assignment) == Some("=")
                && assignment.child_by_field_name("left").is_some_and(|left| {
                    left.kind() == "member_access_expression"
                        && expression_name(left, source) == Some(property)
                        && left.child_by_field_name("expression").is_some_and(|base| {
                            base.kind() == "identifier" && node_text(base, source) == name
                        })
                })
                && assignment
                    .child_by_field_name("right")
                    .is_some_and(|right| {
                        right.kind() == "boolean_literal" && node_text(right, source) == "true"
                    })
        })
}

/// csharpsquid:S2092 and csharpsquid:S3330 — session cookies without
/// `Secure` travel over plain HTTP, and cookies without `HttpOnly` are
/// readable from scripts. Bound: cookies created and configured inside
/// one member body, tracked by storage name.
fn check_cookie_security_flags(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        for (creation, name) in cookie_creations(body, source) {
            if !cookie_sets_property_true(body, source, name, "Secure") {
                issues.push(issue(
                    language,
                    "S2092",
                    format!("Enable the 'Secure' flag on cookie '{name}'."),
                    range_of(creation),
                ));
            }
            if !cookie_sets_property_true(body, source, name, "HttpOnly") {
                issues.push(issue(
                    language,
                    "S3330",
                    format!("Mark cookie '{name}' 'HttpOnly' to block script access."),
                    range_of(creation),
                ));
            }
        }
    }
    issues
}

/// Whether this operand reads like a boolean: literals, comparisons,
/// negations, logical chains, or `Is*`/`Has*`/`Can*`/`Should*` names.
fn looks_boolean_expression(expression: Node<'_>, source: &str) -> bool {
    match expression.kind() {
        "boolean_literal" => true,
        "binary_expression" => matches!(
            operator_of(expression),
            Some("==" | "!=" | "<" | "<=" | ">" | ">=" | "&&" | "||")
        ),
        "prefix_unary_expression" => unary_operator(expression) == Some("!"),
        "identifier" => {
            let name = node_text(expression, source);
            ["Is", "Has", "Can", "Should"].iter().any(|prefix| {
                name.strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_uppercase()))
            })
        }
        _ => false,
    }
}

/// Whether this expression sits inside a control structure's condition.
fn condition_encloses(expression: Node<'_>) -> bool {
    let (start, end) = (expression.start_byte(), expression.end_byte());
    for ancestor in ancestors_of(expression) {
        match ancestor.kind() {
            "block"
            | "method_declaration"
            | "constructor_declaration"
            | "accessor_declaration"
            | "local_function_statement" => return false,
            "if_statement" | "while_statement" | "for_statement" | "do_statement" => {
                if let Some(condition) = ancestor.child_by_field_name("condition")
                    && condition.start_byte() <= start
                    && end <= condition.end_byte()
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// csharpsquid:S2178 — boolean conditions need short-circuit `&&`/`||`;
/// bitwise operators evaluate both sides and misread intent. Bound:
/// only condition positions, and only operands that read as booleans by
/// shape or naming convention.
fn check_short_circuit_logic(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(expression)
            || !matches!(operator_of(expression), Some("&" | "|"))
            || !condition_encloses(expression)
        {
            continue;
        }
        let Some((left, right)) = binary_operands(expression) else {
            continue;
        };
        if looks_boolean_expression(left, source) && looks_boolean_expression(right, source) {
            issues.push(issue(
                language,
                "S2178",
                "Use '&&' or '||' for this boolean combination.",
                range_of(expression),
            ));
        }
    }
    issues
}

/// File-mode members granting access beyond the owner.
const WORLD_WRITABLE_MODE_MEMBERS: [&str; 3] = ["OthersWrite", "OthersExecute", "GroupWrite"];

/// csharpsquid:S2612 — files writable or executable by group/others
/// invite tampering. Bound: spelled `UnixFileMode.<Member>` values;
/// raw octal modes stay out of scope.
fn check_world_writable_file_modes(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["member_access_expression"])
        .into_iter()
        .filter(|access| !is_error_tainted(*access))
        .filter(|access| {
            access
                .child_by_field_name("expression")
                .is_some_and(|qualifier| node_text(qualifier, source) == "UnixFileMode")
        })
        .filter(|access| {
            WORLD_WRITABLE_MODE_MEMBERS.contains(&expression_name(*access, source).unwrap_or(""))
        })
        .map(|access| {
            issue(
                language,
                "S2612",
                "This file mode grants access beyond the owner; restrict it.",
                range_of(access),
            )
        })
        .collect()
}

/// csharpsquid:S2755 — DTD-enabled XML parsers accept entity-expansion
/// and external-entity attacks.
fn check_xxe_vulnerable_parsers(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for assignment in collect_kinds(root, &["assignment_expression"]) {
        if is_error_tainted(assignment) || operator_of(assignment) != Some("=") {
            continue;
        }
        let Some(left) = assignment.child_by_field_name("left") else {
            continue;
        };
        let Some(right) = assignment.child_by_field_name("right") else {
            continue;
        };
        let enables_dtd = expression_name(left, source) == Some("DtdProcessing")
            && left.kind() == "member_access_expression"
            && expression_name(right, source) == Some("Parse");
        let allows_dtd = expression_name(left, source) == Some("ProhibitDtd")
            && right.kind() == "boolean_literal"
            && node_text(right, source) == "false";
        if enables_dtd || allows_dtd {
            issues.push(issue(
                language,
                "S2755",
                "Restrict this XML parser's DTD handling to prevent XXE attacks.",
                range_of(assignment),
            ));
        }
    }
    issues
}

/// Reflection lookups that reach non-public state.
const REFLECTION_MEMBER_LOOKUPS: [&str; 8] = [
    "GetMethod",
    "GetField",
    "GetProperty",
    "GetEvent",
    "GetConstructor",
    "GetMember",
    "InvokeMember",
    "SetValue",
];

/// Binding flags mentioned anywhere in an invocation's arguments.
fn uses_binding_flags(invocation: Node<'_>, source: &str, wanted: &[&str]) -> bool {
    invocation_arguments(invocation).iter().any(|argument| {
        collect_kinds(*argument, &["member_access_expression"])
            .into_iter()
            .any(|access| wanted.contains(&expression_name(access, source).unwrap_or("")))
    })
}

/// csharpsquid:S3011 — reflecting over non-public members escalates
/// accessibility beyond what the type author exposed.
fn check_reflection_accessibility_escalation(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| {
            REFLECTION_MEMBER_LOOKUPS.contains(&callee_name(*call, source).unwrap_or(""))
        })
        .filter(|call| {
            uses_binding_flags(*call, source, &["NonPublic"])
                && uses_binding_flags(*call, source, &["Instance", "Static"])
        })
        .map(|call| {
            issue(
                language,
                "S3011",
                "Reflecting over non-public members bypasses accessibility checks.",
                range_of(call),
            )
        })
        .collect()
}

/// csharpsquid:S3925 — implementing `ISerializable` promises the
/// serialization constructor and a `GetObjectData` override; missing
/// either breaks deserialization.
fn check_iserializable_contract(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_declaration in collect_kinds(root, &["class_declaration"]) {
        if is_error_tainted(class_declaration)
            || !base_simple_names(class_declaration, source).contains(&"ISerializable")
        {
            continue;
        }
        let members = type_members(class_declaration);
        let has_serialization_ctor = members.iter().any(|member| {
            member.kind() == "constructor_declaration"
                && parameters_of(*member).iter().any(|parameter| {
                    parameter
                        .child_by_field_name("type")
                        .is_some_and(|type_node| {
                            simple_name(node_text(type_node, source)) == "SerializationInfo"
                        })
                })
        });
        let has_get_object_data = members.iter().any(|member| {
            member.kind() == "method_declaration"
                && member
                    .child_by_field_name("name")
                    .is_some_and(|name| node_text(name, source) == "GetObjectData")
        });
        if !has_serialization_ctor || !has_get_object_data {
            issues.push(issue(
                language,
                "S3925",
                "Complete the 'ISerializable' implementation: add the serialization constructor and 'GetObjectData'.",
                range_of(name_anchor(class_declaration)),
            ));
        }
    }
    issues
}

/// csharpsquid:S4036 — launching a bare command name resolves through
/// `PATH`, so which binary runs depends on the caller's environment.
fn check_path_resolved_commands(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| {
            let receiver =
                invocation_receiver(*call).and_then(|base| expression_name(base, source));
            callee_name(*call, source) == Some("Start") && receiver == Some("Process")
        })
        .filter(|call| {
            let arguments = invocation_arguments(*call);
            arguments.len() == 1
                && arguments[0]
                    .children(&mut arguments[0].walk())
                    .find(tree_sitter::Node::is_named)
                    .is_some_and(|value| {
                        value.kind() == "string_literal" && {
                            let command = literal_inner_text(value, source);
                            !command.contains(['/', '\\']) && !command.starts_with('.')
                        }
                    })
        })
        .map(|call| {
            issue(
                language,
                "S4036",
                "Launch this command by explicit path instead of relying on 'PATH'.",
                range_of(call),
            )
        })
        .collect()
}

/// csharpsquid:S4159 — an `[Export(typeof(I))]` part must actually
/// implement the exported contract `I`. Bound: same-file classes;
/// contracts declared elsewhere are assumed satisfied.
fn check_exported_contracts_implemented(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_declaration in collect_kinds(root, &["class_declaration"]) {
        if is_error_tainted(class_declaration) {
            continue;
        }
        for attribute in collect_kinds(class_declaration, &["attribute"]) {
            let exports = attribute
                .children(&mut attribute.walk())
                .find(tree_sitter::Node::is_named)
                .is_some_and(|name| node_text(name, source).ends_with("Export"));
            if !exports {
                continue;
            }
            let contract = attribute_argument_texts(attribute, source)
                .into_iter()
                .find_map(simple_name_of_typeof);
            let implemented = contract.as_ref().is_some_and(|contract| {
                base_simple_names(class_declaration, source).contains(&contract.as_str())
            });
            if let Some(contract) = contract
                && !implemented
            {
                issues.push(issue(
                    language,
                    "S4159",
                    format!("This class exports '{contract}' without implementing it."),
                    range_of(name_anchor(class_declaration)),
                ));
            }
        }
    }
    issues
}

/// Whether the type carries `[Shared]` or a shared `PartCreationPolicy`.
fn is_shared_mef_part(type_node: Node<'_>, source: &str) -> bool {
    has_any_attribute(type_node, source, &["Shared"])
        || collect_kinds(type_node, &["attribute"])
            .iter()
            .any(|attribute| {
                attribute_argument_texts(*attribute, source)
                    .iter()
                    .any(|text| text.ends_with("CreationPolicy.Shared") || *text == "Shared")
                    && {
                        let name = attribute
                            .children(&mut attribute.walk())
                            .find(tree_sitter::Node::is_named)
                            .map(|name| node_text(name, source).ends_with("PartCreationPolicy"));
                        name == Some(true)
                    }
            })
}

/// csharpsquid:S4277 — MEF parts marked shared must be resolved through
/// the container; `new` bypasses the sharing scope and creates a second
/// instance. Bound: same-file parts and creations.
fn check_shared_parts_created_directly(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let shared_names: std::collections::HashSet<&str> =
        collect_kinds(root, &TYPE_DECLARATION_KINDS)
            .into_iter()
            .filter(|type_node| is_shared_mef_part(*type_node, source))
            .filter_map(|type_node| type_node.child_by_field_name("name"))
            .map(|name| node_text(name, source))
            .collect();
    if shared_names.is_empty() {
        return Vec::new();
    }
    collect_kinds(root, &["object_creation_expression"])
        .into_iter()
        .filter(|creation| !is_error_tainted(*creation))
        .filter(|creation| {
            creation
                .child_by_field_name("type")
                .is_some_and(|type_node| {
                    shared_names.contains(simple_name(node_text(type_node, source)))
                })
        })
        .map(|creation| {
            issue(
                language,
                "S4277",
                "Resolve this shared MEF part through the container instead of 'new'.",
                range_of(creation),
            )
        })
        .collect()
}

/// csharpsquid:S4433 — anonymous LDAP binds leak directory data to
/// anyone who can reach the server.
fn check_unauthenticated_ldap_connections(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["object_creation_expression"])
        .into_iter()
        .filter(|creation| !is_error_tainted(*creation))
        .filter(|creation| {
            creation
                .child_by_field_name("type")
                .is_some_and(|type_node| {
                    simple_name(node_text(type_node, source)) == "DirectoryEntry"
                })
        })
        .filter(|creation| {
            let arguments = invocation_arguments(*creation);
            arguments.len() == 1
                && arguments[0]
                    .children(&mut arguments[0].walk())
                    .find(tree_sitter::Node::is_named)
                    .is_some_and(|value| {
                        value.kind() == "string_literal"
                            && literal_inner_text(value, source)
                                .to_ascii_uppercase()
                                .starts_with("LDAP")
                    })
        })
        .map(|creation| {
            issue(
                language,
                "S4433",
                "Set credentials or a secure authentication type on this LDAP connection.",
                range_of(creation),
            )
        })
        .collect()
}

/// Validation that throws argument exceptions eagerly: a `throw` of an
/// `Argument*` exception or a `ThrowIf*` guard call.
fn is_validation_statement(statement: Node<'_>, source: &str) -> bool {
    let throws_argument_exception = statement.kind() == "throw_statement"
        && collect_kinds(statement, &["object_creation_expression"])
            .into_iter()
            .any(|creation| {
                creation
                    .child_by_field_name("type")
                    .is_some_and(|type_node| {
                        simple_name(node_text(type_node, source)).starts_with("Argument")
                    })
            });
    throws_argument_exception
        || collect_kinds(statement, &["invocation_expression"])
            .into_iter()
            .any(|call| callee_name(call, source).is_some_and(|name| name.starts_with("ThrowIf")))
}

/// Validation statements of a body, in document order.
fn validation_statements<'t>(body: Node<'t>, source: &str) -> Vec<Node<'t>> {
    collect_kinds(body, &["throw_statement", "expression_statement"])
        .into_iter()
        .filter(|statement| !is_error_tainted(*statement))
        .filter(|statement| is_validation_statement(*statement, source))
        .collect()
}

/// csharpsquid:S4456 — iterators defer their whole body until
/// enumeration, so argument validation inside them surfaces far from
/// the buggy call site.
fn check_iterator_parameter_validation(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        let Some(body) = body_of(method) else {
            continue;
        };
        if collect_kinds(body, &["yield_statement"]).is_empty() {
            continue;
        }
        for validation in validation_statements(body, source) {
            issues.push(issue(
                language,
                "S4456",
                "Move this validation out of the iterator; it will not run until enumeration.",
                range_of(validation),
            ));
        }
    }
    issues
}

/// csharpsquid:S4457 — async methods should reject bad input before the
/// first suspension point; validations after an `await` surface late.
fn check_async_parameter_validation(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if !has_modifier(&modifiers_of(method, source), "async") {
            continue;
        }
        let Some(body) = body_of(method) else {
            continue;
        };
        let Some(first_await) = collect_kinds(body, &["await_expression"])
            .into_iter()
            .map(|await_expression| await_expression.start_byte())
            .min()
        else {
            continue;
        };
        for validation in validation_statements(body, source) {
            if validation.start_byte() > first_await {
                issues.push(issue(
                    language,
                    "S4457",
                    "Validate these parameters before the first 'await' in this method.",
                    range_of(validation),
                ));
            }
        }
    }
    issues
}

/// Whether this target name suggests recording a point in time.
fn records_instant(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    [
        "time", "date", "stamp", "created", "modified", "updated", "expires", "seen",
    ]
    .iter()
    .any(|marker| lowered.contains(marker))
}

/// Stores of `DateTime.Now` into instant-named targets, in document
/// order: `(target name, node)`.
fn local_now_stores<'t, 's>(body: Node<'t>, source: &'s str) -> Vec<(&'s str, Node<'t>)> {
    let mut stores = Vec::new();
    for assignment in collect_kinds(body, &["assignment_expression"]) {
        let Some(left) = assignment.child_by_field_name("left") else {
            continue;
        };
        let Some(target) = assignment_target_name(left, source) else {
            continue;
        };
        if let Some(right) = assignment.child_by_field_name("right")
            && node_text(right, source) == "DateTime.Now"
        {
            stores.push((target, assignment));
        }
    }
    for declarator in collect_kinds(body, &["variable_declarator"]) {
        let Some(name) = declarator.child_by_field_name("name") else {
            continue;
        };
        if let Some(value) = declarator_initializer(declarator, name)
            && node_text(value, source) == "DateTime.Now"
        {
            stores.push((node_text(name, source), declarator));
        }
    }
    stores
}

/// csharpsquid:S6563 — recorded instants belong in UTC so timelines
/// stay comparable across zones and daylight-saving changes. Bound:
/// targets whose name reads like an instant (`*Time`, `Created`,
/// `Modified`, …) stored from `DateTime.Now`.
fn check_local_time_instants(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        for (name, store) in local_now_stores(body, source) {
            if records_instant(name) {
                issues.push(issue(
                    language,
                    "S6563",
                    format!("Record '{name}' in UTC with 'DateTime.UtcNow'."),
                    range_of(store),
                ));
            }
        }
    }
    issues
}

/// Fields, properties, locals, and parameters typed `DateTimeOffset…`.
fn datetimeoffset_target_names(root: Node<'_>, source: &str) -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();
    let push_offset_declarators =
        |declaration: Node<'_>, names: &mut std::collections::HashSet<String>| {
            for declarator in collect_kinds(declaration, &["variable_declarator"]) {
                if let Some(name) = declarator.child_by_field_name("name") {
                    names.insert(node_text(name, source).to_owned());
                }
            }
        };
    for declaration in collect_kinds(root, &["field_declaration", "variable_declaration"]) {
        if declaration
            .child_by_field_name("type")
            .is_some_and(|type_node| node_text(type_node, source).starts_with("DateTimeOffset"))
        {
            push_offset_declarators(declaration, &mut names);
        }
    }
    for property in collect_kinds(root, &["property_declaration"]) {
        if property
            .child_by_field_name("type")
            .is_some_and(|type_node| node_text(type_node, source).starts_with("DateTimeOffset"))
            && let Some(name) = property.child_by_field_name("name")
        {
            names.insert(node_text(name, source).to_owned());
        }
    }
    for parameter in collect_kinds(root, &["parameter"]) {
        if let Some(type_node) = parameter.child_by_field_name("type")
            && node_text(type_node, source).starts_with("DateTimeOffset")
            && let Some(name) = parameter.child_by_field_name("name")
        {
            names.insert(node_text(name, source).to_owned());
        }
    }
    names
}

/// csharpsquid:S6566 — `DateTimeOffset` targets must not be filled from
/// bare `DateTime` values, which carry no offset and silently adopt the
/// machine zone. Bound: same-file `DateTimeOffset` declarations.
fn check_datetime_into_datetimeoffset(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let offsets = datetimeoffset_target_names(root, source);
    if offsets.is_empty() {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        for (name, store) in local_now_stores(body, source) {
            if offsets.contains(name) {
                issues.push(issue(
                    language,
                    "S6566",
                    format!("Construct '{name}' from a 'DateTimeOffset' so the offset survives."),
                    range_of(store),
                ));
            }
        }
    }
    issues
}

/// UI-text property names whose values users can see.
const LOCALIZABLE_TEXT_MEMBERS: [&str; 6] =
    ["Text", "Caption", "Title", "Header", "Label", "ToolTip"];

/// Base types whose members render on screen.
const UI_BASE_TYPES: [&str; 5] = ["Form", "Control", "UserControl", "Page", "Window"];

/// csharpsquid:S4055 — literals assigned to visible UI text cannot be
/// translated. Bound: string-literal stores into `Text`-family members
/// of types deriving a known UI base.
fn check_literals_in_localizable_members(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_declaration in collect_kinds(root, &["class_declaration"]) {
        if !base_simple_names(class_declaration, source)
            .iter()
            .any(|base| UI_BASE_TYPES.contains(base))
        {
            continue;
        }
        for assignment in collect_kinds(class_declaration, &["assignment_expression"]) {
            if is_error_tainted(assignment) || operator_of(assignment) != Some("=") {
                continue;
            }
            let Some(right) = assignment.child_by_field_name("right") else {
                continue;
            };
            if right.kind() != "string_literal"
                || !LOCALIZABLE_TEXT_MEMBERS.contains(
                    &expression_name(
                        assignment.child_by_field_name("left").unwrap_or(right),
                        source,
                    )
                    .unwrap_or(""),
                )
            {
                continue;
            }
            issues.push(issue(
                language,
                "S4055",
                "Move this literal into a resource so it can be localized.",
                range_of(assignment),
            ));
        }
    }
    issues
}

/// csharpsquid:S4057 — single-argument `Convert.To*` calls parse with
/// the machine culture; data conversions need an explicit format
/// provider. Overload resolution is approximated by argument count.
fn check_culture_less_convert_calls(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| {
            invocation_receiver(*call)
                .is_some_and(|receiver| expression_name(receiver, source) == Some("Convert"))
                && callee_name(*call, source).is_some_and(|name| name.starts_with("To"))
        })
        .filter(|call| invocation_arguments(*call).len() == 1)
        .map(|call| {
            issue(
                language,
                "S4057",
                "Pass an 'IFormatProvider' to make this conversion culture-independent.",
                range_of(call),
            )
        })
        .collect()
}

/// Whether the method's first parameter carries the `this` modifier.
fn has_this_modifier(method: Node<'_>, source: &str) -> bool {
    parameters_of(method)
        .first()
        .is_some_and(|first| node_text(*first, source).trim_start().starts_with("this"))
}

/// csharpsquid:S4226 — extension methods living next to the extended
/// type couple every importer of that type to the extensions. Bound:
/// extended types declared in the same file count as "same namespace".
fn check_extension_methods_next_to_extended_types(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let declared_types: std::collections::HashSet<String> =
        collect_kinds(root, &TYPE_DECLARATION_KINDS)
            .into_iter()
            .filter_map(|type_node| type_node.child_by_field_name("name"))
            .map(|name| node_text(name, source).to_owned())
            .collect();
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if !has_this_modifier(method, source) || is_error_tainted(method) {
            continue;
        }
        let extends_declared = parameters_of(method)
            .first()
            .and_then(|first| first.child_by_field_name("type"))
            .is_some_and(|type_node| {
                declared_types.contains(simple_name(node_text(type_node, source)))
            });
        if extends_declared {
            issues.push(issue(
                language,
                "S4226",
                "Move this extension method into a dedicated namespace.",
                range_of(name_anchor(method)),
            ));
        }
    }
    issues
}

/// Acquire/release invocations by lock-object text, document order:
/// `(method, object text, node)`.
fn lock_operations<'a, 't>(
    body: Node<'t>,
    source: &'a str,
    acquire_names: &[&str],
    release_names: &[&str],
) -> Vec<(&'a str, &'a str, Node<'t>)> {
    collect_kinds(body, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter_map(|call| {
            let method = callee_name(call, source)?;
            let is_acquire = acquire_names.contains(&method);
            let is_release = release_names.contains(&method);
            if !is_acquire && !is_release {
                return None;
            }
            // Reader/writer releases take no argument, so prefer the
            // receiver as the pairing key and fall back to the argument.
            let key = invocation_receiver(call)
                .map(|receiver| node_text(receiver, source))
                .or_else(|| {
                    invocation_arguments(call)
                        .into_iter()
                        .next()
                        .map(|argument| node_text(argument, source))
                })?;
            Some((method, key, call))
        })
        .collect()
}

/// csharpsquid:S7131 — reader/writer lock scopes must nest: releasing
/// the wrong mode deadlocks or corrupts the protection.
fn check_reader_writer_lock_modes(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    const ACQUIRE: [&str; 2] = ["AcquireReaderLock", "AcquireWriterLock"];
    const RELEASE: [&str; 2] = ["ReleaseReaderLock", "ReleaseWriterLock"];
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        let operations = lock_operations(body, source, &ACQUIRE, &RELEASE);
        for (index, (method, object, node)) in operations.iter().enumerate() {
            if RELEASE.contains(method) {
                continue;
            }
            let wanted_release = if *method == ACQUIRE[0] {
                RELEASE[0]
            } else {
                RELEASE[1]
            };
            let matched = operations[index + 1..]
                .iter()
                .any(|(later_method, later_object, _)| {
                    later_method == &wanted_release && later_object == object
                });
            if !matched {
                issues.push(issue(
                    language,
                    "S7131",
                    format!("Call '{wanted_release}' for this lock before returning."),
                    range_of(*node),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S7133 — locks acquired in one method and released in
/// another hide their pairing from every reader. Bound: Monitor
/// enter/exit pairs resolved inside one member body.
fn check_monitor_released_outside_method(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        let operations = monitor_operations(body, source);
        for (index, (method, object, node)) in operations.iter().enumerate() {
            if *method == "Exit" {
                continue;
            }
            let released =
                operations[index + 1..]
                    .iter()
                    .any(|(exit_method, exit_object, exit_call)| {
                        *exit_method == "Exit"
                            && exit_object == object
                            && exit_call.start_byte() > node.end_byte()
                    });
            if !released {
                issues.push(issue(
                    language,
                    "S7133",
                    "Release this lock in the same method that acquired it.",
                    range_of(*node),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S4583 — every delegate `BeginInvoke` needs a matching
/// `EndInvoke` on the same receiver or the async machinery leaks.
fn check_unpaired_delegate_begin_invoke(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        let end_invokes: Vec<&str> = collect_kinds(body, &["invocation_expression"])
            .into_iter()
            .filter(|call| callee_name(*call, source) == Some("EndInvoke"))
            .filter_map(|call| invocation_receiver(call))
            .map(|receiver| node_text(receiver, source))
            .collect();
        for call in collect_kinds(body, &["invocation_expression"]) {
            if callee_name(call, source) != Some("BeginInvoke") || is_error_tainted(call) {
                continue;
            }
            let paired = invocation_receiver(call)
                .is_some_and(|receiver| end_invokes.contains(&node_text(receiver, source)));
            if !paired {
                issues.push(issue(
                    language,
                    "S4583",
                    "Call 'EndInvoke' for this 'BeginInvoke'.",
                    range_of(call),
                ));
            }
        }
    }
    issues
}

/// Certificate-validation callback properties.
const CERT_VALIDATION_CALLBACKS: [&str; 2] = [
    "ServerCertificateValidationCallback",
    "ServerCertificateCustomValidationCallback",
];

/// csharpsquid:S4830 — callbacks that accept any certificate disable
/// TLS server verification entirely.
fn check_permissive_certificate_callbacks(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for assignment in collect_kinds(root, &["assignment_expression"]) {
        if operator_of(assignment) != Some("=") {
            continue;
        }
        let Some(left) = assignment.child_by_field_name("left") else {
            continue;
        };
        if !CERT_VALIDATION_CALLBACKS.contains(&expression_name(left, source).unwrap_or("")) {
            continue;
        }
        let Some(right) = assignment.child_by_field_name("right") else {
            continue;
        };
        let accepts_everything = match right.kind() {
            "lambda_expression" => lambda_shape(right, source).is_some_and(|(_, body)| {
                body.kind() == "boolean_literal" && node_text(body, source) == "true"
            }),
            _ => false,
        };
        if accepts_everything {
            issues.push(issue(
                language,
                "S4830",
                "Validate the certificate chain here instead of accepting everything.",
                range_of(assignment),
            ));
        }
    }
    issues
}

/// csharpsquid:S5034 — a `ValueTask` may be consumed exactly once;
/// awaiting it twice corrupts state. Bound: locals and parameters typed
/// `ValueTask…`, consumption via `await`/`.Result`/`.AsTask()`.
fn check_value_task_consumed_once(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let value_task_locals: std::collections::HashSet<String> =
        collect_kinds(root, &["variable_declarator"])
            .into_iter()
            .filter(|declarator| {
                declarator
                    .parent()
                    .and_then(|parent| parent.child_by_field_name("type"))
                    .is_some_and(|type_node| {
                        simple_name(node_text(type_node, source)) == "ValueTask"
                    })
            })
            .filter_map(|declarator| declarator.child_by_field_name("name"))
            .map(|name| node_text(name, source).to_owned())
            .collect();
    if value_task_locals.is_empty() {
        return Vec::new();
    }
    let mut consumed: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut issues = Vec::new();
    let mut record_consumption = |name: Option<&str>, node: Node<'_>, issues: &mut Vec<Issue>| {
        if let Some(name) = name
            && value_task_locals.contains(name)
        {
            if consumed.contains(name) {
                issues.push(issue(
                    language,
                    "S5034",
                    format!("'{name}' is consumed more than once."),
                    range_of(node),
                ));
            }
            consumed.insert(name.to_owned());
        }
    };
    for await_expression in collect_kinds(root, &["await_expression"]) {
        let operand = first_named_child(await_expression);
        record_consumption(
            operand
                .filter(|operand| operand.kind() == "identifier")
                .map(|operand| node_text(operand, source)),
            await_expression,
            &mut issues,
        );
    }
    for access in collect_kinds(root, &["member_access_expression"]) {
        let member = expression_name(access, source).unwrap_or("");
        if matches!(member, "Result" | "AsTask" | "GetAwaiter") {
            let base = access.child_by_field_name("expression");
            record_consumption(
                base.filter(|base| base.kind() == "identifier")
                    .map(|base| node_text(base, source)),
                access,
                &mut issues,
            );
        }
    }
    issues
}

/// csharpsquid:S6377 — an XML signature check nobody acts on protects
/// nothing. Bound: discarded `CheckSignature` results.
fn check_discarded_signature_checks(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["expression_statement"])
        .into_iter()
        .filter(|statement| !is_error_tainted(*statement))
        .filter_map(|statement| first_named_child(statement))
        .filter(|expression| {
            expression.kind() == "invocation_expression"
                && callee_name(*expression, source) == Some("CheckSignature")
        })
        .map(|call| {
            issue(
                language,
                "S6377",
                "Act on the result of this signature validation.",
                range_of(call),
            )
        })
        .collect()
}

/// ILogger-style logging methods taking `(level, exception, template…)`.
const STRUCTURED_LOG_METHODS: [&str; 7] = [
    "Log",
    "LogTrace",
    "LogDebug",
    "LogInformation",
    "LogWarning",
    "LogError",
    "LogCritical",
];

/// Names bound by catch clauses in the body.
fn caught_exception_names(body: Node<'_>, source: &str) -> std::collections::HashSet<String> {
    collect_kinds(body, &["catch_clause"])
        .into_iter()
        .filter_map(|clause| {
            collect_kinds(clause, &["catch_declaration"])
                .into_iter()
                .next()
        })
        .filter_map(|declaration| declaration.child_by_field_name("name"))
        .map(|name| node_text(name, source).to_owned())
        .collect()
}

/// csharpsquid:S6668 — the exception belongs right after the message
/// template; passing it later drops it from structured output. Bound:
/// caught-variable names resolved within one body.
fn check_misplaced_log_exceptions(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        let caught = caught_exception_names(body, source);
        if caught.is_empty() {
            continue;
        }
        for call in collect_kinds(body, &["invocation_expression"]) {
            if !STRUCTURED_LOG_METHODS.contains(&callee_name(call, source).unwrap_or(""))
                || is_error_tainted(call)
            {
                continue;
            }
            let arguments = invocation_arguments(call);
            let template_index = arguments.iter().position(|argument| {
                first_named_child(*argument).is_some_and(|value| value.kind() == "string_literal")
            });
            let Some(template_index) = template_index else {
                continue;
            };
            let late_exception = arguments[template_index + 1..].iter().any(|argument| {
                collect_kinds(*argument, &["identifier"])
                    .into_iter()
                    .any(|identifier| caught.contains(node_text(identifier, source)))
            });
            if late_exception {
                issues.push(issue(
                    language,
                    "S6668",
                    "Pass the exception directly after the message template.",
                    range_of(call),
                ));
            }
        }
    }
    issues
}

/// csharpsquid:S6781 — signing keys built from literal byte arrays live
/// forever in source control and leak with the repo.
fn check_hardcoded_jwt_signing_keys(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    collect_kinds(root, &["object_creation_expression"])
        .into_iter()
        .filter(|creation| !is_error_tainted(*creation))
        .filter(|creation| {
            creation
                .child_by_field_name("type")
                .is_some_and(|type_node| {
                    simple_name(node_text(type_node, source)) == "SymmetricSecurityKey"
                })
        })
        .filter(|creation| {
            collect_kinds(*creation, &["invocation_expression"])
                .into_iter()
                .any(|call| {
                    callee_name(call, source) == Some("GetBytes")
                        && invocation_arguments(call).iter().any(|argument| {
                            first_named_child(*argument)
                                .is_some_and(|value| value.kind() == "string_literal")
                        })
                })
                || invocation_arguments(*creation).iter().any(|argument| {
                    first_named_child(*argument)
                        .is_some_and(|value| value.kind() == "string_literal")
                })
        })
        .map(|creation| {
            issue(
                language,
                "S6781",
                "Load this signing key from configuration instead of hard-coding it.",
                range_of(creation),
            )
        })
        .collect()
}

/// csharpsquid:S6803 — query binding only runs for routable components;
/// `[SupplyParameterFromQuery]` without a route silently never binds.
/// Bound: same-file classes; Razor routes outside `.razor` files are not
/// visible here.
fn check_query_binding_without_route(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_declaration in collect_kinds(root, &["class_declaration"]) {
        if is_error_tainted(class_declaration) {
            continue;
        }
        let routable = attributes_of(class_declaration, source)
            .iter()
            .any(|name| name.ends_with("Route") || name.ends_with("RouteAttribute"));
        if routable {
            continue;
        }
        for property in type_members(class_declaration)
            .into_iter()
            .filter(|member| member.kind() == "property_declaration")
        {
            if has_any_attribute(property, source, &["SupplyParameterFromQuery"]) {
                issues.push(issue(
                    language,
                    "S6803",
                    "This component has no route, so its query parameters never bind.",
                    range_of(name_anchor(property)),
                ));
            }
        }
    }
    issues
}

/// HTTP-mutation verbs under which model binding under-posts.
const MUTATION_HTTP_VERBS: [&str; 3] = ["HttpPost", "HttpPut", "HttpPatch"];

/// csharpsquid:S6964 — missing JSON fields leave value-type inputs at
/// their defaults, so absent data becomes valid-looking zeros. Bound:
/// actions in classes carrying `[ApiController]`; nullable and
/// attributed parameters stay exempt.
fn check_under_posting_value_type_inputs(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_declaration in collect_kinds(root, &["class_declaration"]) {
        if !has_any_attribute(class_declaration, source, &["ApiController"]) {
            continue;
        }
        for action in type_members(class_declaration)
            .into_iter()
            .filter(|member| member.kind() == "method_declaration")
        {
            if !MUTATION_HTTP_VERBS
                .iter()
                .any(|verb| has_any_attribute(action, source, &[verb]))
            {
                continue;
            }
            for parameter in parameters_of(action) {
                let is_value_type =
                    parameter
                        .child_by_field_name("type")
                        .is_some_and(|type_node| {
                            let text = node_text(type_node, source);
                            !text.contains('?')
                                && matches!(
                                    simple_name(text),
                                    "int"
                                        | "long"
                                        | "short"
                                        | "byte"
                                        | "bool"
                                        | "decimal"
                                        | "double"
                                        | "float"
                                        | "Guid"
                                        | "DateTime"
                                )
                        });
                if is_value_type && !is_attributed(parameter, source) {
                    issues.push(issue(
                        language,
                        "S6964",
                        "Make this value-type input nullable or validate presence to prevent under-posting.",
                        range_of(parameter),
                    ));
                }
            }
        }
    }
    issues
}

/// csharpsquid:S6966 — fire-and-forget async work dies unobserved and
/// swallows failures. Bound: convention — methods named `*Async` called
/// as bare statements are treated as awaitable.
fn check_discarded_async_calls(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["expression_statement"])
        .into_iter()
        .filter(|statement| !is_error_tainted(*statement))
        .filter_map(|statement| first_named_child(statement))
        .filter(|expression| expression.kind() == "invocation_expression")
        .filter(|call| callee_name(*call, source).is_some_and(|name| name.ends_with("Async")))
        .map(|call| {
            issue(
                language,
                "S6966",
                "Await this asynchronous operation or observe its result.",
                range_of(call),
            )
        })
        .collect()
}

/// Copy-producing members that defeat shared references.
const COLLECTION_COPY_METHODS: [&str; 3] = ["ToList", "ToArray", "Clone"];

/// csharpsquid:S2365 — getters that copy their collection allocate a
/// fresh list per read and mislead callers into thinking they own the
/// data. Bound: `get` accessors and expression-bodied properties.
fn check_copying_property_getters(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for accessor in collect_kinds(root, &["accessor_declaration"]) {
        if accessor_keyword(accessor, source) != "get" || is_error_tainted(accessor) {
            continue;
        }
        for call in collect_kinds(accessor, &["invocation_expression"]) {
            if COLLECTION_COPY_METHODS.contains(&callee_name(call, source).unwrap_or("")) {
                issues.push(issue(
                    language,
                    "S2365",
                    "This getter copies the collection on every read; expose a read-only view instead.",
                    range_of(call),
                ));
            }
        }
    }
    issues
}

// ======================================================================
// Tier B — receiver-type LINQ/performance family (local type map)
//
// A minimal type map feeds these rules: locals declared `var` from a
// `new T(...)` right side, explicitly typed locals, fields, properties,
// and parameters. Method return values, casts, and anything crossing
// member boundaries stay unresolved — those receivers produce no
// findings by design.
// ======================================================================

/// Collection types with instance members that beat their LINQ
/// counterparts.
const LIST_LIKE_TYPES: [&str; 4] = ["List", "IList", "IReadOnlyList", "ArrayList"];

/// The inferred type of an expression, if the local type map knows it.
fn mapped_receiver_type(
    expression: Node<'_>,
    source: &str,
    type_map: &std::collections::HashMap<String, String>,
) -> Option<String> {
    match expression.kind() {
        "identifier" => type_map.get(node_text(expression, source)).cloned(),
        "member_access_expression" => expression_name(expression, source).map(str::to_owned),
        _ => None,
    }
}

/// Builds the per-member local type map: declarations whose type is
/// spelled (`List<int> xs`) or inferable from a constructor initializer
/// (`var xs = new List<int>()`).
fn build_local_type_map(body: Node<'_>, source: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for declaration in collect_kinds(body, &["variable_declaration", "field_declaration"]) {
        // `field_declaration` wraps its `variable_declaration`, so fall
        // back to that child when the declaration has no direct type.
        let type_node = declaration.child_by_field_name("type").or_else(|| {
            collect_kinds(declaration, &["variable_declaration"])
                .into_iter()
                .next()
                .and_then(|variable| variable.child_by_field_name("type"))
        });
        let Some(type_node) = type_node else {
            continue;
        };
        let explicit_type = simple_name(node_text(type_node, source));
        for declarator in collect_kinds(declaration, &["variable_declarator"]) {
            let Some(name) = declarator.child_by_field_name("name") else {
                continue;
            };
            let name_text = node_text(name, source).to_owned();
            if explicit_type != "var" {
                map.insert(name_text, explicit_type.to_owned());
                continue;
            }
            let inferred = declarator_initializer(declarator, name).and_then(|value| {
                value
                    .child_by_field_name("type")
                    .filter(|_| value.kind() == "object_creation_expression")
                    .map(|type_node| simple_name(node_text(type_node, source)).to_owned())
            });
            if let Some(inferred) = inferred {
                map.insert(name_text, inferred);
            }
        }
    }
    for parameter in collect_kinds(body, &["parameter"]) {
        if let (Some(type_node), Some(name)) = (
            parameter.child_by_field_name("type"),
            parameter.child_by_field_name("name"),
        ) {
            map.insert(
                node_text(name, source).to_owned(),
                simple_name(node_text(type_node, source)).to_owned(),
            );
        }
    }
    for property in collect_kinds(body, &["property_declaration"]) {
        if let (Some(type_node), Some(name)) = (
            property.child_by_field_name("type"),
            property.child_by_field_name("name"),
        ) {
            map.insert(
                node_text(name, source).to_owned(),
                simple_name(node_text(type_node, source)).to_owned(),
            );
        }
    }
    map
}

/// csharpsquid:S6602/S6603/S6605/S6608/S6609/S6613 — list-like and
/// set-like receivers have dedicated instance members that beat the
/// LINQ extensions. Bound: only receivers resolvable through the local
/// type map; unknown receivers are never flagged.
fn check_linq_receivers(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    // One type map per enclosing type, built on first use.
    let mut cached_scope: Option<(usize, std::collections::HashMap<String, String>)> = None;
    for call in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(call) {
            continue;
        }
        let scope_root = nearest_ancestor_of_kinds(call, &TYPE_DECLARATION_KINDS).unwrap_or(root);
        let scope_id = scope_root.id();
        if cached_scope.as_ref().map(|(id, _)| *id) != Some(scope_id) {
            cached_scope = Some((scope_id, build_local_type_map(scope_root, source)));
        }
        let Some((_, type_map)) = cached_scope.as_ref() else {
            continue;
        };
        let Some(receiver) = invocation_receiver(call) else {
            continue;
        };
        let Some(receiver_type) = mapped_receiver_type(receiver, source, type_map) else {
            continue;
        };
        let callee = callee_name(call, source).unwrap_or("");
        let arguments = invocation_arguments(call);
        let replacement = if LIST_LIKE_TYPES.contains(&receiver_type.as_str()) {
            match (callee, arguments.len()) {
                ("FirstOrDefault", 1..=2) => Some(("Find", "S6602")),
                ("All", 1) => Some(("TrueForAll", "S6603")),
                ("Any", 1) => Some(("Exists", "S6605")),
                ("ElementAt", 1) | ("First" | "Last", 0) => Some(("indexing", "S6608")),
                _ => None,
            }
        } else {
            match (callee, arguments.len()) {
                ("Min", 0)
                    if matches!(
                        receiver_type.as_str(),
                        "SortedSet" | "ImmutableSortedSet" | "HashSet"
                    ) =>
                {
                    Some(("Min property", "S6609"))
                }
                ("Max", 0)
                    if matches!(receiver_type.as_str(), "SortedSet" | "ImmutableSortedSet") =>
                {
                    Some(("Max property", "S6609"))
                }
                ("First" | "Last", 0) if receiver_type == "LinkedList" => {
                    Some(("First/Last property", "S6613"))
                }
                _ => None,
            }
        };
        if let Some((suggestion, rule)) = replacement {
            let message =
                format!("Use '{suggestion}' on this '{receiver_type}' instead of '{callee}'.");
            issues.push(issue(language, rule, message, range_of(call)));
        }
    }
    issues
}

/// Gathers every Tier-B framework/API pattern-match issue.
fn framework_api_issues(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_cookie_security_flags(root, source, language));
    issues.extend(check_short_circuit_logic(root, source, language));
    issues.extend(check_world_writable_file_modes(root, source, language));
    issues.extend(check_xxe_vulnerable_parsers(root, source, language));
    issues.extend(check_reflection_accessibility_escalation(
        root, source, language,
    ));
    issues.extend(check_iserializable_contract(root, source, language));
    issues.extend(check_path_resolved_commands(root, source, language));
    issues.extend(check_exported_contracts_implemented(root, source, language));
    issues.extend(check_shared_parts_created_directly(root, source, language));
    issues.extend(check_unauthenticated_ldap_connections(
        root, source, language,
    ));
    issues.extend(check_iterator_parameter_validation(root, source, language));
    issues.extend(check_async_parameter_validation(root, source, language));
    issues.extend(check_local_time_instants(root, source, language));
    issues.extend(check_datetime_into_datetimeoffset(root, source, language));
    issues.extend(check_literals_in_localizable_members(
        root, source, language,
    ));
    issues.extend(check_culture_less_convert_calls(root, source, language));
    issues.extend(check_extension_methods_next_to_extended_types(
        root, source, language,
    ));
    issues.extend(check_reader_writer_lock_modes(root, source, language));
    issues.extend(check_monitor_released_outside_method(
        root, source, language,
    ));
    issues.extend(check_unpaired_delegate_begin_invoke(root, source, language));
    issues.extend(check_permissive_certificate_callbacks(
        root, source, language,
    ));
    issues.extend(check_value_task_consumed_once(root, source, language));
    issues.extend(check_discarded_signature_checks(root, source, language));
    issues.extend(check_misplaced_log_exceptions(root, source, language));
    issues.extend(check_hardcoded_jwt_signing_keys(root, source, language));
    issues.extend(check_query_binding_without_route(root, source, language));
    issues.extend(check_under_posting_value_type_inputs(
        root, source, language,
    ));
    issues.extend(check_discarded_async_calls(root, source, language));
    issues.extend(check_copying_property_getters(root, source, language));
    issues.extend(check_linq_receivers(root, source, language));
    issues
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{AnalyzerOptions, CsLanguage, analyze, language_for_extension};

    #[test]
    fn extensions_map_to_csharp() {
        assert_eq!(language_for_extension("cs"), Some(CsLanguage::CSharp));
        assert_eq!(language_for_extension("py"), None);
    }

    #[test]
    fn clean_csharp_parses_with_metrics() {
        let report = analyze(
            PathBuf::from("test.cs"),
            "int total = 1;\ntotal = total + total;\n",
            CsLanguage::CSharp,
            &AnalyzerOptions::default(),
        );
        assert_eq!(report.language, "csharpsquid");
        assert!(report.issues.is_empty());
        assert_eq!(report.metrics.lines, 2);
        assert!(report.metrics.code_lines > 0);
        assert_eq!(report.metrics.comment_lines, 0);
    }

    #[test]
    fn comment_lines_are_counted_separately() {
        let report = analyze(
            PathBuf::from("test.cs"),
            "// leading note\nclass A { }\n/* block\ncomment */\n",
            CsLanguage::CSharp,
            &AnalyzerOptions::default(),
        );
        assert_eq!(report.metrics.comment_lines, 3);
        assert_eq!(report.metrics.code_lines, 1);
    }

    #[test]
    fn line_length_honors_option_with_exact_boundary_clean() {
        let options = AnalyzerOptions {
            maximum_line_length: 13,
            ..Default::default()
        };
        let at_limit = analyze(
            PathBuf::from("t.cs"),
            "const int ab;\n",
            CsLanguage::CSharp,
            &options,
        );
        assert!(at_limit.issues.is_empty());

        let over_limit = analyze(
            PathBuf::from("t.cs"),
            "const int abc;\n",
            CsLanguage::CSharp,
            &options,
        );
        assert_eq!(over_limit.issues.len(), 1);
        assert_eq!(over_limit.issues[0].rule_key, "csharpsquid:S103");
        assert_eq!(over_limit.issues[0].range.start.line, 1);
        assert_eq!(
            over_limit.issues[0].message,
            "This line exceeds the maximum allowed length of 13 characters."
        );
    }

    #[test]
    fn broken_source_neither_panics_nor_emits_issues() {
        let report = analyze(
            PathBuf::from("t.cs"),
            "class {{{ ;;; ???\n",
            CsLanguage::CSharp,
            &AnalyzerOptions::default(),
        );
        assert!(report.issues.is_empty());
    }
    fn with_key<'a>(
        report: &'a hoonarqube_ir::FileReport,
        key: &str,
    ) -> Vec<&'a hoonarqube_ir::Issue> {
        report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == key)
            .collect()
    }

    fn analyze_options(source: &str, options: &AnalyzerOptions) -> hoonarqube_ir::FileReport {
        analyze(PathBuf::from("t.cs"), source, CsLanguage::CSharp, options)
    }
    fn analyze_default(source: &str) -> hoonarqube_ir::FileReport {
        analyze(
            PathBuf::from("t.cs"),
            source,
            CsLanguage::CSharp,
            &AnalyzerOptions::default(),
        )
    }

    #[test]
    fn s104_flags_files_over_the_loc_threshold() {
        let options = AnalyzerOptions {
            maximum_file_loc_threshold: 3,
            ..Default::default()
        };
        let over = analyze_options("class A\n{\n}\nint b;\n", &options);
        let flagged = with_key(&over, "csharpsquid:S104");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);

        let at_limit = analyze_options("class A\n{\n}\nint b;\n", &AnalyzerOptions::default());
        assert!(with_key(&at_limit, "csharpsquid:S104").is_empty());
    }

    #[test]
    fn s105_reports_leading_tab_characters() {
        let report = analyze_default("\tint x;\nclass A\n{\n}\n");
        let flagged = with_key(&report, "csharpsquid:S105");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
        assert_eq!(flagged[0].range.start.column, 0);
        assert_eq!(
            flagged[0].message,
            "Replace all tab characters in this file by spaces."
        );

        let clean = analyze_default("    int x;\nclass A\n{\n}\n");
        assert!(with_key(&clean, "csharpsquid:S105").is_empty());
    }

    #[test]
    fn s113_requires_trailing_newline() {
        let report = analyze_default("class A {}");
        let flagged = with_key(&report, "csharpsquid:S113");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
        assert_eq!(flagged[0].range.start.column, 10);
        assert_eq!(
            flagged[0].message,
            "Add a new line at the end of this file."
        );

        assert!(with_key(&analyze_default(""), "csharpsquid:S113").is_empty());
        assert!(with_key(&analyze_default("class A {}\n"), "csharpsquid:S113").is_empty());
    }

    #[test]
    fn s1109_flags_indented_closing_braces() {
        let report = analyze_default("class A\n{\n    }\n");
        let flagged = with_key(&report, "csharpsquid:S1109");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[0].range.start.column, 4);

        let clean = analyze_default("class A\n{\n}\n");
        assert!(with_key(&clean, "csharpsquid:S1109").is_empty());
    }

    #[test]
    fn s122_flags_second_statement_on_a_line() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        int a = 1; int b = 2;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S122");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[0].range.start.column, 19);

        let clean = analyze_default(
            "class A\n{\n    void M()\n    {\n        int a = 1;\n        int b = 2;\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S122").is_empty());
    }

    #[test]
    fn s3972_flags_inline_else_catch_and_finally() {
        let report = analyze_default(
            "class A\n{\n    void M(int x)\n    {\n        if (x > 0) { } else { }\n        try { } catch (System.Exception) { } finally { }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3972");
        assert_eq!(flagged.len(), 3);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
        assert_eq!(flagged[2].range.start.line, 6);

        let clean = analyze_default(
            "class A\n{\n    void M(int x)\n    {\n        if (x > 0)\n        {\n        }\n        else\n        {\n        }\n        try\n        {\n        }\n        catch (System.Exception)\n        {\n        }\n        finally\n        {\n        }\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S3972").is_empty());
    }

    #[test]
    fn s3973_flags_unindented_conditional_bodies() {
        let report = analyze_default(
            "class A\n{\n    void M(int x)\n    {\n        if (x > 0)\n        x++;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3973");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 6);
        assert_eq!(
            flagged[0].message,
            "Indent this statement to make its scope obvious."
        );

        let indented = analyze_default(
            "class A\n{\n    void M(int x)\n    {\n        if (x > 0)\n            x++;\n    }\n}\n",
        );
        assert!(with_key(&indented, "csharpsquid:S3973").is_empty());

        let same_line = analyze_default(
            "class A\n{\n    void M(int x)\n    {\n        if (x > 0) x++;\n    }\n}\n",
        );
        assert!(with_key(&same_line, "csharpsquid:S3973").is_empty());
    }

    #[test]
    fn s1659_flags_multiple_declarators_on_one_line() {
        let report = analyze_default("class A\n{\n    int a = 1, b = 2;\n}\n");
        let flagged = with_key(&report, "csharpsquid:S1659");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[0].range.start.column, 15);

        let split_lines = analyze_default("class A\n{\n    int a = 1,\n        b = 2;\n}\n");
        assert!(with_key(&split_lines, "csharpsquid:S1659").is_empty());
    }

    #[test]
    fn s4663_flags_only_empty_comments() {
        let report = analyze_default("//\nclass A {}\n/* */\n");
        let flagged = with_key(&report, "csharpsquid:S4663");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 1);
        assert_eq!(flagged[1].range.start.line, 3);

        let clean = analyze_default("///\n// note\nclass A {}\n/* filled */\n");
        assert!(with_key(&clean, "csharpsquid:S4663").is_empty());
    }

    #[test]
    fn s125_flags_commented_out_code_runs() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        // if (ready)\n        // {\n        //     Launch();\n        // }\n        int x = 1;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S125");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);

        let prose = analyze_default(
            "class A\n{\n    // This method computes the total.\n    // See the design notes.\n    void M() { }\n}\n",
        );
        assert!(with_key(&prose, "csharpsquid:S125").is_empty());
    }

    #[test]
    fn s2148_boundary_separators_and_radixes() {
        let report = analyze_default(
            "class A\n{\n    int[] sizes = { 9999, 10000, 10_000, 0xABCD, 123456789012 };\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2148");
        assert_eq!(flagged.len(), 2);

        let reals = analyze_default(
            "class A\n{\n    double a = 10000.5;\n    double b = 9999.5;\n    var c = 2e5;\n    var d = 2e3;\n}\n",
        );
        let flagged_reals = with_key(&reals, "csharpsquid:S2148");
        assert_eq!(flagged_reals.len(), 2);
        assert_eq!(flagged_reals[0].range.start.line, 3);
        assert_eq!(flagged_reals[1].range.start.line, 5);
    }

    #[test]
    fn s1451_header_modes() {
        let options = AnalyzerOptions {
            header_format: "/// MIT Licensed".to_string(),
            ..Default::default()
        };
        let compliant = analyze_options("/// MIT Licensed\nclass A {}\n", &options);
        assert!(with_key(&compliant, "csharpsquid:S1451").is_empty());

        let missing = analyze_options("class A {}\n", &options);
        let flagged = with_key(&missing, "csharpsquid:S1451");
        assert_eq!(flagged.len(), 1);
        assert_eq!(
            flagged[0].range.start,
            hoonarqube_ir::Pos { line: 1, column: 0 }
        );

        let regex_mode = AnalyzerOptions {
            header_format: "/// MIT Licensed".to_string(),
            header_is_regular_expression: true,
            ..Default::default()
        };
        let skipped = analyze_options("class A {}\n", &regex_mode);
        assert!(with_key(&skipped, "csharpsquid:S1451").is_empty());

        let disabled = analyze_options("class A {}\n", &AnalyzerOptions::default());
        assert!(with_key(&disabled, "csharpsquid:S1451").is_empty());
    }

    #[test]
    fn s100_method_and_property_names() {
        let report = analyze_default(
            "class A\n{\n    void bad_name() { }\n    void GoodName() { }\n    int bad_prop { get; set; }\n    int GoodProp { get; set; }\n    void IFoo.lower_case() { }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S100");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[1].range.start.line, 5);
        assert!(flagged[0].message.contains("this method"));
        assert!(flagged[1].message.contains("this property"));
    }

    #[test]
    fn s101_type_names_by_kind() {
        let report = analyze_default(
            "class lower_class { }\ninterface iface { }\nstruct point { }\nenum kind { A }\nrecord Point(int X, int Y);\n",
        );
        let flagged = with_key(&report, "csharpsquid:S101");
        assert_eq!(flagged.len(), 4);
        assert!(flagged[0].message.contains("this class"));
        assert!(flagged[1].message.contains("this interface"));
        assert!(flagged[2].message.contains("this struct"));
        assert!(flagged[3].message.contains("this enum"));
    }

    #[test]
    fn s2342_enum_formats_split_on_flags_attribute() {
        let report = analyze_default(
            "[Flags]\nenum HttpMethod { A }\nenum httpCode { A }\n[Flags]\nenum HttpMethods { A }\nenum HttpCodes { A }\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2342");
        assert_eq!(flagged.len(), 2);
        assert!(
            flagged[0]
                .message
                .contains("^([A-Z]{1,3}[a-z0-9]+)*([A-Z]{2})?s$")
        );
        assert!(
            flagged[1]
                .message
                .contains("^([A-Z]{1,3}[a-z0-9]+)*([A-Z]{2})?$")
        );
    }

    #[test]
    fn s2344_enum_suffixes() {
        let report =
            analyze_default("enum ColorsEnum { A }\nenum AccessFlags { A }\nenum Colors { A }\n");
        let flagged = with_key(&report, "csharpsquid:S2344");
        assert_eq!(flagged.len(), 2);
        assert!(flagged[0].message.contains("Enum"));
        assert!(flagged[1].message.contains("Flags"));
    }

    #[test]
    fn s3376_extended_type_suffixes_required() {
        let report = analyze_default(
            "class Foo : Exception { }\nclass BarException : Exception { }\nclass Args : EventArgs { }\nclass PayloadArgs : EventArgs { }\nclass Plain { }\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3376");
        assert_eq!(flagged.len(), 3);
        assert!(flagged[0].message.contains("Exception"));
        assert!(flagged[1].message.contains("EventArgs"));
        assert!(flagged[2].message.contains("EventArgs"));
    }

    #[test]
    fn s3872_parameter_duplicating_method_name() {
        let report = analyze_default("class A\n{\n    void M(int m, int other) { }\n}\n");
        let flagged = with_key(&report, "csharpsquid:S3872");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[0].range.start.column, 15);
    }

    #[test]
    fn s4041_type_names_matching_namespaces() {
        let report =
            analyze_default("namespace Data\n{\n    class Loader { }\n}\nclass data { }\n");
        let flagged = with_key(&report, "csharpsquid:S4041");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
        assert!(flagged[0].message.contains("Data"));
    }

    #[test]
    fn s4059_getter_methods_duplicating_properties() {
        let report = analyze_default(
            "class A\n{\n    int Foo => 1;\n    int GetFoo() => 2;\n    int GetBar() => 3;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4059");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 4);
        assert!(flagged[0].message.contains("\"Foo\""));
    }

    #[test]
    fn s4136_overloads_must_be_grouped() {
        let separated = analyze_default(
            "class A\n{\n    void Alpha() { }\n    void Beta() { }\n    void Alpha(int a) { }\n}\n",
        );
        let flagged = with_key(&separated, "csharpsquid:S4136");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);

        let grouped = analyze_default(
            "class A\n{\n    void Alpha() { }\n    void Alpha(int a) { }\n    void Beta() { }\n    void Beta(int b) { }\n}\n",
        );
        assert!(with_key(&grouped, "csharpsquid:S4136").is_empty());
    }

    #[test]
    fn s4261_async_suffix_directions_and_skips() {
        let report = analyze_default(
            "class A\n{\n    async Task Go() { await Task.Yield(); }\n    Task DoneAsync() => Task.CompletedTask;\n    async Task RunAsync() { await Task.Yield(); }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4261");
        assert_eq!(flagged.len(), 2);
        assert!(flagged[0].message.starts_with("Add the \"Async\" suffix"));
        assert!(
            flagged[1]
                .message
                .starts_with("Remove the \"Async\" suffix")
        );

        let overrides = analyze_default(
            "class Base { public virtual async Task XAsync() => Task.CompletedTask; }\nclass Derived : Base\n{\n    public override Task XAsync() => Task.CompletedTask;\n}\n",
        );
        assert!(with_key(&overrides, "csharpsquid:S4261").is_empty());

        let interfaces = analyze_default("interface I\n{\n    Task DoAsync();\n}\n");
        assert!(with_key(&interfaces, "csharpsquid:S4261").is_empty());
    }

    #[test]
    fn s6669_logger_member_names() {
        let report = analyze_default(
            "class A\n{\n    ILogger log;\n    ILogger _logger;\n    ILogger Logger;\n    ILogger factory;\n    IFormatter bogus;\n}\nclass B\n{\n    ILogger Log { get; } = null!;\n    ILogger writer { get; } = null!;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S6669");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 6);
        assert_eq!(flagged[1].range.start.line, 12);
        assert!(flagged[0].message.contains("^_?[Ll]og(ger)?$"));
    }

    #[test]
    fn issues_are_sorted_by_position() {
        let report = analyze_default("\tint x;\nclass A {}\n");
        let positions: Vec<(u32, u32)> = report
            .issues
            .iter()
            .map(|issue| (issue.range.start.line, issue.range.start.column))
            .collect();
        let mut sorted = positions.clone();
        sorted.sort_unstable();
        assert_eq!(positions, sorted);
    }

    #[test]
    fn s1104_flags_public_instance_fields_only() {
        let report = analyze_default(
            "class Widget\n{\n    public int Count;\n}\nclass Hidden\n{\n    private int count;\n}\nclass Shared\n{\n    public static int total;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1104");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);

        let clean = analyze_default("class Widget\n{\n    private int count;\n}\n");
        assert!(with_key(&clean, "csharpsquid:S1104").is_empty());
    }

    #[test]
    fn s2357_flags_non_private_fields_but_not_constants() {
        let report = analyze_default(
            "class Widget\n{\n    internal int cached;\n}\nclass Quiet\n{\n    private int cached;\n}\nclass Limits\n{\n    public const int Max = 3;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2357");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s2223_flags_visible_static_fields_even_readonly() {
        let report = analyze_default(
            "class Cache\n{\n    internal static int counter;\n}\nclass Scale\n{\n    public static readonly int Factor = 1;\n}\nclass Locked\n{\n    private const int Cap = 9;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2223");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[1].range.start.line, 7);
    }

    #[test]
    fn s2339_flags_public_constants_only() {
        let report = analyze_default(
            "class Limits\n{\n    public const int Max = 3;\n}\nclass PrivateLimits\n{\n    private const int Cap = 2;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2339");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s2386_flags_mutable_public_static_fields() {
        let report = analyze_default(
            "class Counter\n{\n    public static int hits;\n}\nclass Frozen\n{\n    public static readonly int start = 1;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2386");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s2156_flags_protected_members_in_sealed_types() {
        let report = analyze_default(
            "sealed class Fixed\n{\n    public void Grow()\n    {\n    }\n\n    protected void Shrink()\n    {\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2156");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);
    }

    #[test]
    fn s2290_flags_virtual_field_like_events() {
        let report = analyze_default(
            "class Broadcaster\n{\n    public virtual event System.EventHandler Changed;\n\n    public event System.EventHandler Stopped;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2290");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s3442_flags_public_constructors_in_abstract_classes() {
        let report = analyze_default(
            "abstract class Plant\n{\n    public Plant()\n    {\n    }\n}\nabstract class Seed\n{\n    protected Seed()\n    {\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3442");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s3453_flags_uninstantiable_private_constructor_classes() {
        let source = "class Secret\n{\n    private Secret()\n    {\n    }\n}\nclass Gateway\n{\n    private Gateway()\n    {\n    }\n\n    public static Gateway Create()\n    {\n        return new Gateway();\n    }\n}\npartial class Split\n{\n    private Split()\n    {\n    }\n}\n";
        let report = analyze_default(source);
        let flagged = with_key(&report, "csharpsquid:S3453");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
    }

    #[test]
    fn s3871_flags_non_public_exception_types() {
        let report = analyze_default(
            "class FaultError : Exception\n{\n}\npublic class AppFailure : Exception\n{\n}\nclass Container\n{\n    private class InnerError : Exception\n    {\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3871");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 1);
        assert_eq!(flagged[1].range.start.line, 9);
    }

    #[test]
    fn s4060_flags_unsealed_attribute_classes() {
        let report = analyze_default(
            "class HintAttribute : Attribute\n{\n}\nsealed class TagAttribute : Attribute\n{\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4060");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
    }

    #[test]
    fn s4035_flags_unsealed_iequatable_implementations() {
        let report = analyze_default(
            "class Amount : IEquatable<Amount>\n{\n    public bool Equals(Amount other)\n    {\n        return true;\n    }\n}\nsealed class Ratio : IEquatable<Ratio>\n{\n    public bool Equals(Ratio other)\n    {\n        return true;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4035");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
    }

    #[test]
    fn s3260_flags_undecided_private_types() {
        let report = analyze_default(
            "class Outer\n{\n    class Inner\n    {\n    }\n}\nclass Zoo\n{\n    class Beast\n    {\n    }\n\n    sealed class Tamed : Beast\n    {\n    }\n\n    record Token(int id);\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3260");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[1].range.start.line, 17);
    }

    #[test]
    fn s3059_flags_members_more_visible_than_their_container() {
        let report = analyze_default(
            "public class Registry\n{\n    internal class Cache\n    {\n        public void Reset()\n        {\n        }\n\n        private void Prime()\n        {\n        }\n    }\n}\ninternal class Vault\n{\n    public class Door\n    {\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3059");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 16);
    }

    #[test]
    fn s2360_flags_optional_parameters_except_overrides() {
        let report = analyze_default(
            "class Base\n{\n    public virtual void Configure(int retries = 3)\n    {\n    }\n}\nclass Child : Base\n{\n    public override void Configure(int retries = 3)\n    {\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2360");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s3874_flags_out_and_ref_parameters_except_overrides() {
        let report = analyze_default(
            "class Parser\n{\n    public bool TryRead(out int value)\n    {\n        value = 0;\n        return true;\n    }\n\n    public void Swap(ref int left)\n    {\n    }\n\n    public void Plain(int value)\n    {\n    }\n}\nclass DerivedParser : Parser\n{\n    public override bool TryRead(out int value)\n    {\n        value = 1;\n        return true;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3874");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[1].range.start.line, 9);
    }

    #[test]
    fn s3447_flags_optional_attribute_on_ref_parameters() {
        let report = analyze_default(
            "class Binder\n{\n    public void Store([Optional] ref int target)\n    {\n    }\n\n    public void Keep(ref int target)\n    {\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3447");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s3450_requires_optional_next_to_default_parameter_value() {
        let report = analyze_default(
            "class Loader\n{\n    public void Load([DefaultParameterValue(5)] int count)\n    {\n    }\n\n    public void Ready([DefaultParameterValue(5)] [Optional] int count)\n    {\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3450");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s3451_flags_default_value_on_parameters() {
        let report = analyze_default(
            "class Saver\n{\n    public void Save([DefaultValue(3)] int retries)\n    {\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3451");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s3343_requires_caller_information_parameters_last() {
        let bad = analyze_default(
            "class Tracer\n{\n    public void Track([CallerMemberName] string member = \"\", int depth = 0)\n    {\n    }\n}\n",
        );
        let flagged = with_key(&bad, "csharpsquid:S3343");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);

        let last = analyze_default(
            "class Tracer\n{\n    public void Track(int depth, [CallerMemberName] string member = \"\")\n    {\n    }\n}\n",
        );
        assert!(with_key(&last, "csharpsquid:S3343").is_empty());

        let before_params = analyze_default(
            "class Tracer\n{\n    public void Track(int depth, [CallerMemberName] string member = \"\", params object[] rest)\n    {\n    }\n}\n",
        );
        assert!(with_key(&before_params, "csharpsquid:S3343").is_empty());
    }

    #[test]
    fn s4214_and_s4200_flag_pinvoke_declarations_by_visibility() {
        let report = analyze_default(
            "class Audio\n{\n    [DllImport(\"user32.dll\")]\n    public static extern bool Beep(uint frequency, uint duration);\n\n    [DllImport(\"user32.dll\")]\n    internal static extern bool Chime(uint frequency);\n}\n",
        );
        let visible = with_key(&report, "csharpsquid:S4214");
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].range.start.line, 4);
        let wrapped = with_key(&report, "csharpsquid:S4200");
        assert_eq!(wrapped.len(), 2);
    }

    #[test]
    fn s4000_flags_pointer_types_in_public_signatures() {
        let report = analyze_default(
            "class Memory\n{\n    public void Copy(int* source, int count)\n    {\n    }\n\n    internal int* Head()\n    {\n        return null;\n    }\n\n    public int* Tail()\n    {\n        return null;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4000");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[1].range.start.line, 12);
    }

    #[test]
    fn s3967_flags_multidimensional_arrays_not_jagged() {
        let report = analyze_default(
            "class Board\n{\n    private int[,] grid;\n\n    private int[][] rows;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3967");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s2368_flags_public_methods_with_multidimensional_array_parameters() {
        let report = analyze_default(
            "class Painter\n{\n    public void Draw(int[,] pixels)\n    {\n    }\n\n    internal void Blend(int[,] pixels)\n    {\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2368");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s4022_flags_non_int_enum_storage() {
        let report = analyze_default(
            "enum Tiny : byte\n{\n    One\n}\nenum Plain\n{\n    Two\n}\nenum Wide : int\n{\n    Three\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4022");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
    }

    #[test]
    fn s4017_flags_nested_generics_in_signatures() {
        let report = analyze_default(
            "class Graph\n{\n    public void Load(List<Dictionary<string, int>> data)\n    {\n    }\n\n    public List<List<int>> Build()\n    {\n        return new List<List<int>>();\n    }\n\n    public void Save(Dictionary<string, int> data)\n    {\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4017");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[1].range.start.line, 7);
    }

    #[test]
    fn s2436_caps_generic_arities_with_boundaries_clean() {
        let report = analyze_default(
            "class Pairing<A, B>\n{\n}\nclass Tripling<A, B, C>\n{\n}\nclass Handler\n{\n    public void Trio<TOne, TTwo, TThree>(TOne first, TTwo second, TThree third)\n    {\n    }\n\n    public void Quad<TOne, TTwo, TThree, TFour>(TOne first, TTwo second, TThree third, TFour fourth)\n    {\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2436");
        assert_eq!(flagged.len(), 2);
        assert_eq!(
            flagged[0].message,
            "Reduce the number of type parameters (3 > 2)."
        );
        assert_eq!(
            flagged[1].message,
            "Reduce the number of type parameters (4 > 3)."
        );

        let options = AnalyzerOptions {
            maximum_generic_parameters_for_methods: 1,
            ..Default::default()
        };
        let tightened = analyze_options(
            "class Solo\n{\n    public void Duo<TOne, TTwo>(TOne first, TTwo second)\n    {\n    }\n}\n",
            &options,
        );
        let capped = with_key(&tightened, "csharpsquid:S2436");
        assert_eq!(capped.len(), 1);
        assert_eq!(
            capped[0].message,
            "Reduce the number of type parameters (2 > 1)."
        );
        assert!(with_key(&analyze_default("class Solo\n{\n    public void Duo<TOne, TTwo>(TOne first, TTwo second)\n    {\n    }\n}\n"), "csharpsquid:S2436").is_empty());
    }

    #[test]
    fn s4018_flags_method_type_parameters_missing_from_parameter_list() {
        let report = analyze_default(
            "class Sender\n{\n    public void Send<TMessage>(TMessage message)\n    {\n    }\n\n    public void Lose<TLost>()\n    {\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4018");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);
    }

    #[test]
    fn s2326_flags_unused_type_parameters_constraints_count_as_usage() {
        let report = analyze_default(
            "class Box<TContent>\n{\n    private int size;\n}\nclass Crate<TItem>\n{\n    private TItem item;\n\n    public bool Matches<TOther>(TOther candidate)\n        where TOther : TItem\n    {\n        return false;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2326");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
    }

    #[test]
    fn s3168_flags_async_void_methods() {
        let report = analyze_default(
            "class Worker\n{\n    public async void FireAsync()\n    {\n    }\n\n    public async System.Threading.Tasks.Task RunAsync()\n    {\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3168");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s2306_flags_async_await_identifiers_but_not_keywords() {
        let report = analyze_default(
            "int async = 1;\nint await = 2;\n\nclass Sleeper\n{\n    public async void NapAsync()\n    {\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2306");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 1);
        assert_eq!(flagged[1].range.start.line, 2);
    }

    #[test]
    fn s907_flags_goto_statements() {
        let report = analyze_default(
            "class Jumper\n{\n    public void Jump()\n    {\n        goto Done;\nDone:\n        return;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S907");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s1227_flags_break_outside_loops_and_switches() {
        let report = analyze_default(
            "class Runner\n{\n    public void Run(bool again)\n    {\n        if (again)\n        {\n            break;\n        }\n    }\n\n    public void Walk()\n    {\n        while (true)\n        {\n            break;\n        }\n    }\n\n    public int Pick(int number)\n    {\n        switch (number)\n        {\n            case 1:\n                break;\n        }\n        return number;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1227");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);
    }

    #[test]
    fn s6640_flags_unsafe_blocks_and_declarations() {
        let report = analyze_default(
            "class Raw\n{\n    public void Touch()\n    {\n        unsafe\n        {\n            int value = 1;\n        }\n    }\n\n    public unsafe void Direct()\n    {\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S6640");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 11);
        assert_eq!(flagged[0].message, "Remove this unsafe block.");
        assert_eq!(
            flagged[1].message,
            "Remove the 'unsafe' modifier from this declaration."
        );
    }

    #[test]
    fn s4061_flags_arglist_usage() {
        let report = analyze_default(
            "class Varargs\n{\n    public void Call()\n    {\n        Native(1, __arglist);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4061");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s121_requires_curly_braces_on_embedded_statements() {
        let report = analyze_default(
            "class A\n{\n    void M(bool x)\n    {\n        if (x)\n        {\n            DoIt();\n        }\n        while (x)\n            DoIt();\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S121");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 10);

        let clean = analyze_default(
            "class A\n{\n    void M(bool x)\n    {\n        while (x)\n        {\n            DoIt();\n        }\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S121").is_empty());
    }

    #[test]
    fn s108_flags_empty_blocks_but_not_commented_ones() {
        let report = analyze_default(
            "class A\n{\n    void M(bool x)\n    {\n        if (x)\n        {\n        }\n        if (x)\n        {\n            /* note */\n        }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S108");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 6);
    }

    #[test]
    fn s1116_flags_empty_statements() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        ;\n        DoIt();\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1116");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s1110_flags_redundant_parenthesis_pairs() {
        let report = analyze_default(
            "class A\n{\n    int Twice(int x)\n    {\n        return ((x)) + (x);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1110");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s3235_flags_return_and_argument_parentheses() {
        let report = analyze_default(
            "class A\n{\n    int Get(int x)\n    {\n        return (x);\n    }\n    void Use(int y)\n    {\n        Consume((y));\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3235");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 9);

        let clean =
            analyze_default("class A\n{\n    int Get(int x)\n    {\n        return x;\n    }\n}\n");
        assert!(with_key(&clean, "csharpsquid:S3235").is_empty());
    }

    #[test]
    fn s1066_merges_else_less_ifs_holding_one_nested_if() {
        let report = analyze_default(
            "class A\n{\n    void M(bool a, bool b)\n    {\n        if (a)\n        {\n            if (b)\n            {\n                DoIt();\n            }\n        }\n        if (a)\n        {\n            if (b)\n            {\n                DoIt();\n            }\n            else\n            {\n                Stop();\n            }\n        }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1066");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s126_demands_a_terminal_else_on_chains() {
        let open_chain = analyze_default(
            "class A\n{\n    void M(int n)\n    {\n        if (n == 1)\n        {\n            Stop();\n        }\n        else if (n == 2)\n        {\n            Stop();\n        }\n    }\n}\n",
        );
        let flagged = with_key(&open_chain, "csharpsquid:S126");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 9);

        let closed_chain = analyze_default(
            "class A\n{\n    void M(int n)\n    {\n        if (n == 1)\n        {\n            Stop();\n        }\n        else\n        {\n            Stop();\n        }\n    }\n}\n",
        );
        assert!(with_key(&closed_chain, "csharpsquid:S126").is_empty());
    }

    #[test]
    fn s131_requires_a_default_clause() {
        let missing = analyze_default(
            "class A\n{\n    void M(int n)\n    {\n        switch (n)\n        {\n            case 1:\n                break;\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&missing, "csharpsquid:S131").len(), 1);

        let present = analyze_default(
            "class A\n{\n    void M(int n)\n    {\n        switch (n)\n        {\n            case 1:\n                break;\n            default:\n                break;\n        }\n    }\n}\n",
        );
        assert!(with_key(&present, "csharpsquid:S131").is_empty());
    }

    #[test]
    fn s1301_rejects_switches_with_fewer_than_three_cases() {
        let small = analyze_default(
            "class A\n{\n    void M(int n)\n    {\n        switch (n)\n        {\n            case 1:\n                break;\n            case 2:\n                break;\n            default:\n                break;\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&small, "csharpsquid:S1301").len(), 1);

        let boundary = analyze_default(
            "class A\n{\n    void M(int n)\n    {\n        switch (n)\n        {\n            case 1:\n                break;\n            case 2:\n                break;\n            case 3:\n                break;\n            default:\n                break;\n        }\n    }\n}\n",
        );
        assert!(with_key(&boundary, "csharpsquid:S1301").is_empty());
    }

    #[test]
    fn s1479_limits_switch_section_statement_counts() {
        let options = AnalyzerOptions {
            maximum_switch_section_statements: 2,
            ..Default::default()
        };
        let over = analyze_options(
            "class A\n{\n    void M(int n)\n    {\n        switch (n)\n        {\n            case 1:\n                DoIt();\n                DoIt();\n                DoIt();\n                break;\n        }\n    }\n}\n",
            &options,
        );
        assert_eq!(with_key(&over, "csharpsquid:S1479").len(), 1);

        let at_limit = analyze_options(
            "class A\n{\n    void M(int n)\n    {\n        switch (n)\n        {\n            case 1:\n                DoIt();\n                break;\n        }\n    }\n}\n",
            &options,
        );
        assert!(with_key(&at_limit, "csharpsquid:S1479").is_empty());
    }

    #[test]
    fn s1151_limits_switch_section_line_spans() {
        let options = AnalyzerOptions {
            maximum_switch_section_lines: 4,
            ..Default::default()
        };
        let over = analyze_options(
            "class A\n{\n    void M(int n)\n    {\n        switch (n)\n        {\n            case 1:\n                DoIt();\n                DoIt();\n                DoIt();\n                break;\n        }\n    }\n}\n",
            &options,
        );
        assert_eq!(with_key(&over, "csharpsquid:S1151").len(), 1);

        let at_limit = analyze_options(
            "class A\n{\n    void M(int n)\n    {\n        switch (n)\n        {\n            case 1:\n                DoIt();\n                DoIt();\n                break;\n        }\n    }\n}\n",
            &options,
        );
        assert!(with_key(&at_limit, "csharpsquid:S1151").is_empty());
    }

    #[test]
    fn s134_enforces_the_configured_nesting_depth() {
        let nested = "class A\n{\n    void M(bool go, bool ok)\n    {\n        foreach (var item in Items)\n        {\n            while (go)\n            {\n                if (ok)\n                {\n                    DoIt();\n                }\n            }\n        }\n    }\n}\n";
        let options = AnalyzerOptions {
            maximum_nesting_level: 0,
            ..Default::default()
        };
        let report = analyze_options(nested, &options);
        let flagged = with_key(&report, "csharpsquid:S134");
        assert_eq!(flagged[0].range.start.line, 7);
        assert_eq!(flagged[1].range.start.line, 9);

        let relaxed = AnalyzerOptions {
            maximum_nesting_level: 2,

            ..Default::default()
        };
        assert!(with_key(&analyze_options(nested, &relaxed), "csharpsquid:S134").is_empty());
    }

    #[test]
    fn s1199_flags_plain_nested_code_blocks() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        {\n            DoIt();\n        }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1199");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }
    #[test]
    fn s2681_encloses_multiline_embedded_bodies_in_braces() {
        let report = analyze_default(
            "class A\n{\n    void M(int x)\n    {\n        if (x > 0)\n            DoIt(\n                x);\n        if (x > 0)\n        {\n            DoIt(x);\n        }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2681");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 6);

        let braced = analyze_default(
            "class A\n{\n    void M(int x)\n    {\n        if (x > 0)\n        {\n            DoIt(\n                x);\n        }\n    }\n}\n",
        );
        assert!(with_key(&braced, "csharpsquid:S2681").is_empty());
    }

    #[test]
    fn s1821_flags_switches_nested_in_switches() {
        let report = analyze_default(
            "class A\n{\n    void M(int a, int b)\n    {\n        switch (a)\n        {\n            case 1:\n                switch (b)\n                {\n                    case 2:\n                        break;\n                }\n                break;\n        }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1821");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 8);

        let flat = analyze_default(
            "class A\n{\n    void M(int a)\n    {\n        switch (a)\n        {\n            case 1:\n                break;\n        }\n    }\n}\n",
        );
        assert!(with_key(&flat, "csharpsquid:S1821").is_empty());
    }

    #[test]
    fn s4524_keeps_default_first_or_last() {
        let middle = analyze_default(
            "class A\n{\n    void M(int a)\n    {\n        switch (a)\n        {\n            case 1:\n                break;\n            default:\n                break;\n            case 2:\n                break;\n        }\n    }\n}\n",
        );
        let flagged = with_key(&middle, "csharpsquid:S4524");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 9);

        let trailing = analyze_default(
            "class A\n{\n    void M(int a)\n    {\n        switch (a)\n        {\n            case 1:\n                break;\n            case 2:\n                break;\n            default:\n                break;\n        }\n    }\n}\n",
        );
        assert!(with_key(&trailing, "csharpsquid:S4524").is_empty());
    }

    #[test]
    fn s3458_drops_empty_cases_falling_into_default() {
        let report = analyze_default(
            "class A\n{\n    void M(int a)\n    {\n        switch (a)\n        {\n            case 1:\n            default:\n                break;\n            case 2:\n                break;\n        }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3458");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);

        let stacked = analyze_default(
            "class A\n{\n    void M(int a)\n    {\n        switch (a)\n        {\n            case 1:\n            case 2:\n                break;\n            default:\n                break;\n        }\n    }\n}\n",
        );
        assert!(with_key(&stacked, "csharpsquid:S3458").is_empty());
    }

    #[test]
    fn s3532_removes_empty_default_clauses() {
        let report = analyze_default(
            "class A\n{\n    void M(int a)\n    {\n        switch (a)\n        {\n            case 1:\n                break;\n            default:\n        }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3532");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 9);

        let populated = analyze_default(
            "class A\n{\n    void M(int a)\n    {\n        switch (a)\n        {\n            default:\n                break;\n        }\n    }\n}\n",
        );
        assert!(with_key(&populated, "csharpsquid:S3532").is_empty());
    }

    #[test]
    fn s1264_converts_condition_only_for_loops_to_while() {
        let report = analyze_default(
            "class A\n{\n    void M(bool go)\n    {\n        for (;;)\n        {\n            if (!go)\n            {\n                break;\n            }\n        }\n        for (; go; )\n        {\n            DoIt();\n        }\n        for (var i = 0; i < 3; i++)\n        {\n            DoIt();\n        }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1264");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 12);

        let complete = analyze_default(
            "class A\n{\n    void M()\n    {\n        for (var i = 0; i < 3; i++)\n        {\n            DoIt();\n        }\n    }\n}\n",
        );
        assert!(with_key(&complete, "csharpsquid:S1264").is_empty());
    }

    #[test]
    fn s1994_requires_the_increment_to_drive_the_counter() {
        let detached = analyze_default(
            "class A\n{\n    void M()\n    {\n        for (var i = 0; i < 3; )\n        {\n            i = 1;\n        }\n    }\n}\n",
        );
        let flagged = with_key(&detached, "csharpsquid:S1994");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);

        let driven = analyze_default(
            "class A\n{\n    void M()\n    {\n        for (var i = 0; i < 3; i++)\n        {\n            DoIt();\n        }\n    }\n}\n",
        );
        assert!(with_key(&driven, "csharpsquid:S1994").is_empty());
    }

    #[test]
    fn s138_limits_function_body_spans() {
        let options = AnalyzerOptions {
            maximum_function_lines: 2,
            ..Default::default()
        };
        let over = analyze_options(
            "class A\n{\n    void M()\n    {\n        DoIt();\n        DoIt();\n        DoIt();\n    }\n}\n",
            &options,
        );
        let flagged = with_key(&over, "csharpsquid:S138");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);

        let at_limit = AnalyzerOptions {
            maximum_function_lines: 5,
            ..Default::default()
        };
        assert!(
            with_key(&analyze_options(
                "class A\n{\n    void M()\n    {\n        DoIt();\n        DoIt();\n        DoIt();\n    }\n}\n",
                &at_limit
            ), "csharpsquid:S138")
                .is_empty()
        );
    }

    #[test]
    fn s107_limits_method_parameter_counts() {
        let eight = analyze_default(
            "class A\n{\n    void M(int a, int b, int c, int d, int e, int f, int g, int h)\n    {\n        DoIt();\n    }\n}\n",
        );
        let flagged = with_key(&eight, "csharpsquid:S107");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);

        let seven = analyze_default(
            "class A\n{\n    void M(int a, int b, int c, int d, int e, int f, int g)\n    {\n        DoIt();\n    }\n}\n",
        );
        assert!(with_key(&seven, "csharpsquid:S107").is_empty());
    }

    #[test]
    fn s1541_limits_cyclomatic_complexity() {
        let branching = "class A\n{\n    int Score(bool a, bool b, bool c)\n    {\n        if (a && b)\n        {\n            return 1;\n        }\n        return c ? 2 : 3;\n    }\n}\n";
        let strict = AnalyzerOptions {
            maximum_function_complexity_threshold: 3,
            ..Default::default()
        };
        let report = analyze_options(branching, &strict);
        let flagged = with_key(&report, "csharpsquid:S1541");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);

        let tolerant = AnalyzerOptions {
            maximum_function_complexity_threshold: 4,
            ..Default::default()
        };
        assert!(with_key(&analyze_options(branching, &tolerant), "csharpsquid:S1541").is_empty());
    }

    #[test]
    fn s3776_limits_cognitive_complexity_with_nesting_weights() {
        let nested = "class A\n{\n    void M(bool a, bool b)\n    {\n        if (a)\n        {\n            if (b)\n            {\n                DoIt();\n            }\n        }\n    }\n}\n";
        let strict = AnalyzerOptions {
            maximum_cognitive_complexity_threshold: 2,
            ..Default::default()
        };
        let report = analyze_options(nested, &strict);
        let flagged = with_key(&report, "csharpsquid:S3776");
        assert_eq!(flagged[0].range.start.line, 3);

        let tolerant = AnalyzerOptions {
            maximum_cognitive_complexity_threshold: 3,
            ..Default::default()
        };
        assert!(with_key(&analyze_options(nested, &tolerant), "csharpsquid:S3776").is_empty());
    }

    #[test]
    fn s1067_limits_logical_operators_per_expression() {
        let four = analyze_default(
            "class A\n{\n    bool Check(bool a, bool b, bool c, bool d, bool e)\n    {\n        return a && b && c && d && e;\n    }\n}\n",
        );
        let flagged = with_key(&four, "csharpsquid:S1067");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);

        let three = analyze_default(
            "class A\n{\n    bool Check(bool a, bool b, bool c)\n    {\n        return a && b && c;\n    }\n}\n",
        );
        assert!(with_key(&three, "csharpsquid:S1067").is_empty());
    }

    #[test]
    fn s1186_flags_empty_methods_except_attributed_ones() {
        let report = analyze_default(
            "class A\n{\n    void Empty()\n    {\n    }\n\n    [System.Obsolete]\n    void Hook()\n    {\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1186");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s1048_forbids_throwing_finalizers() {
        let report = analyze_default(
            "class A\n{\n    ~A()\n    {\n        throw new System.Exception();\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1048");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);

        let quiet = analyze_default("class A\n{\n    ~A()\n    {\n        Release();\n    }\n}\n");
        assert!(with_key(&quiet, "csharpsquid:S1048").is_empty());
    }

    #[test]
    fn s3880_flags_empty_finalizers() {
        let report = analyze_default("class A\n{\n    ~A()\n    {\n    }\n}\n");
        let flagged = with_key(&report, "csharpsquid:S3880");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s2372_forbids_throwing_property_getters() {
        let report = analyze_default(
            "class A\n{\n    string Name\n    {\n        get\n        {\n            throw new System.Exception();\n        }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2372");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);

        let calm = analyze_default("class A\n{\n    string Name => \"value\";\n}\n");
        assert!(with_key(&calm, "csharpsquid:S2372").is_empty());
    }

    #[test]
    fn s2376_flags_write_only_properties() {
        let report = analyze_default(
            "class A\n{\n    string Name\n    {\n        set\n        {\n            stored = value;\n        }\n    }\n\n    string Both\n    {\n        get\n        {\n            return stored;\n        }\n        set\n        {\n            stored = value;\n        }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2376");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s2292_replaces_trivial_accessor_pairs_with_auto_properties() {
        let report = analyze_default(
            "class A\n{\n    int Value\n    {\n        get { return number; }\n        set { number = value; }\n    }\n\n    int Auto { get; set; }\n\n    int Computed\n    {\n        get { return number + 1; }\n        set { number = value; }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2292");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s1694_demands_abstract_and_concrete_members_on_abstract_classes() {
        let report = analyze_default(
            "abstract class OnlyAbstract\n{\n    public abstract void Go();\n}\n\nabstract class OnlyConcrete\n{\n    public void Walk()\n    {\n        DoIt();\n    }\n}\n\nabstract class Mixed\n{\n    public abstract void Run();\n\n    public void Walk()\n    {\n        DoIt();\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1694");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 1);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s2094_flags_empty_classes_and_records() {
        let report = analyze_default(
            "class Bare\n{\n}\n\nrecord BareRecord;\n\npartial class Split\n{\n}\n\nrecord Positioned(int Id);\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2094");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 1);
        assert_eq!(flagged[1].range.start.line, 5);
    }

    #[test]
    fn s4023_flags_empty_interfaces() {
        let report =
            analyze_default("interface IBare\n{\n}\n\ninterface IFull\n{\n    void Go();\n}\n");
        let flagged = with_key(&report, "csharpsquid:S4023");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
    }

    #[test]
    fn s3261_flags_empty_namespaces() {
        let report = analyze_default(
            "namespace Empty\n{\n}\n\nnamespace Full\n{\n    class Inside\n    {\n        int member;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3261");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
    }

    #[test]
    fn s3903_moves_file_scope_types_into_namespaces() {
        let report = analyze_default(
            "class One\n{\n    int member;\n}\n\nclass Two\n{\n    int member;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3903");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 1);
        assert_eq!(flagged[1].range.start.line, 6);

        let lone = analyze_default("class Solo\n{\n    int member;\n}\n");
        assert!(with_key(&lone, "csharpsquid:S3903").is_empty());
    }
    // -----------------------------------------------------------------
    // A6 — constant-fold patterns
    // -----------------------------------------------------------------

    #[test]
    fn s1764_flags_identical_operands() {
        let report = analyze_default(
            "class A\n{\n    void M(int x)\n    {\n        var d = x - x;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1764");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);

        let clean = analyze_default(
            "class A\n{\n    void M(int x)\n    {\n        var m = x * x;\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S1764").is_empty());
    }

    #[test]
    fn s1862_flags_repeated_else_if_conditions() {
        let report = analyze_default(
            "class A\n{\n    void M(int x)\n    {\n        if (x > 0) { Work(); }\n        else if (x > 0) { More(); }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1862");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 6);

        let clean = analyze_default(
            "class A\n{\n    void M(int x)\n    {\n        if (x > 0) { Work(); }\n        else if (x < 0) { More(); }\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S1862").is_empty());
    }

    #[test]
    fn s3923_flags_fully_identical_branches() {
        let report = analyze_default(
            "class A\n{\n    void M(bool flag)\n    {\n        if (flag) { Run(); }\n        else { Run(); }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3923");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);

        let clean = analyze_default(
            "class A\n{\n    void M(bool flag)\n    {\n        if (flag) { Run(); }\n        else { Stop(); }\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S3923").is_empty());
    }

    #[test]
    fn s1871_flags_duplicate_switch_sections() {
        let report = analyze_default(
            "class A\n{\n    void M(int n)\n    {\n        switch (n)\n        {\n            case 1:\n                Work();\n                break;\n            case 2:\n                Work();\n                break;\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1871").len(), 1);
        assert!(with_key(&report, "csharpsquid:S3626").is_empty());

        let clean = analyze_default(
            "class A\n{\n    void M(int n)\n    {\n        switch (n)\n        {\n            case 1:\n                Work();\n                break;\n            case 2:\n                Rest();\n                break;\n        }\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S1871").is_empty());
    }

    #[test]
    fn s4144_flags_identical_sibling_method_bodies() {
        let report = analyze_default(
            "class A\n{\n    int First()\n    {\n        return Compute(1);\n    }\n\n    int Second()\n    {\n        return Compute(1);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4144");
        assert_eq!(flagged.len(), 1);

        let clean = analyze_default(
            "class A\n{\n    int First()\n    {\n        return Compute(1);\n    }\n\n    int Second()\n    {\n        return Compute(2);\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S4144").is_empty());
    }

    #[test]
    fn s2760_flags_adjacent_repeated_conditions() {
        let report = analyze_default(
            "class A\n{\n    void M(int x)\n    {\n        if (x > 0) { Work(); }\n        if (x > 0) { More(); }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2760");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 6);

        let clean = analyze_default(
            "class A\n{\n    void M(int x)\n    {\n        if (x > 0) { Work(); }\n        if (x < 9) { More(); }\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S2760").is_empty());
    }

    #[test]
    fn s3441_flags_redundant_anonymous_property_names() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        var o = new { Name = Name };\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3441");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);

        let clean = analyze_default(
            "class A\n{\n    void M(string other)\n    {\n        var o = new { Name = other };\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S3441").is_empty());
    }

    #[test]
    fn s3604_flags_self_referential_member_initializers() {
        let report = analyze_default(
            "class A\n{\n    void M(int x)\n    {\n        var p = new Point { X = x, Y = Y };\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3604");
        assert_eq!(flagged.len(), 1);

        let clean = analyze_default(
            "class A\n{\n    void M(int x)\n    {\n        var p = new Point { X = x };\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S3604").is_empty());
    }

    #[test]
    fn s3400_flags_constant_returning_methods() {
        let report =
            analyze_default("class A\n{\n    int Answer()\n    {\n        return 42;\n    }\n}\n");
        let flagged = with_key(&report, "csharpsquid:S3400");
        assert_eq!(flagged.len(), 1);

        let computed =
            analyze_default("class A\n{\n    int Sum()\n    {\n        return 40 + 2;\n    }\n}\n");
        assert!(with_key(&computed, "csharpsquid:S3400").is_empty());

        let entry_point = analyze_options(
            "class A\n{\n    static void Main()\n    {\n        return;\n    }\n}\n",
            &AnalyzerOptions::default(),
        );
        assert!(with_key(&entry_point, "csharpsquid:S3400").is_empty());
    }

    #[test]
    fn s3626_flags_trailing_loop_jumps_only() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        while (KeepGoing())\n        {\n            Step();\n            break;\n        }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3626");
        assert_eq!(flagged[0].range.start.line, 8);

        let falling_through = analyze_default(
            "class A\n{\n    void M(int n)\n    {\n        switch (n)\n        {\n            case 1:\n                Step();\n                break;\n        }\n    }\n}\n",
        );
        assert!(with_key(&falling_through, "csharpsquid:S3626").is_empty());
    }

    #[test]
    fn s1848_and_s3984_split_dropped_creations_by_type() {
        let plain =
            analyze_default("class A\n{\n    void M()\n    {\n        new Widget();\n    }\n}\n");
        assert_eq!(with_key(&plain, "csharpsquid:S1848").len(), 1);
        assert!(with_key(&plain, "csharpsquid:S3984").is_empty());

        let exception = analyze_default(
            "class A\n{\n    void M()\n    {\n        new BoomException(\"why\");\n    }\n}\n",
        );
        assert_eq!(with_key(&exception, "csharpsquid:S3984").len(), 1);
        assert!(with_key(&exception, "csharpsquid:S1848").is_empty());

        let used = analyze_default(
            "class A\n{\n    void M()\n    {\n        var w = new Widget();\n    }\n}\n",
        );
        assert!(with_key(&used, "csharpsquid:S1848").is_empty());
    }

    #[test]
    fn s3717_tracks_not_implemented_throws() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        throw new NotImplementedException(\"later\");\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3717");
        assert_eq!(flagged.len(), 1);

        let done = analyze_default(
            "class A\n{\n    void M()\n    {\n        throw new System.Exception(\"boom\");\n    }\n}\n",
        );
        assert!(with_key(&done, "csharpsquid:S3717").is_empty());
    }

    // -----------------------------------------------------------------
    // A7 — attribute contracts
    // -----------------------------------------------------------------

    #[test]
    fn s1133_and_s1123_distinguish_annotated_obsoletes() {
        let bare = analyze_default("[Obsolete]\nclass Old\n{\n}\n");
        assert_eq!(with_key(&bare, "csharpsquid:S1133").len(), 1);
        assert_eq!(with_key(&bare, "csharpsquid:S1123").len(), 1);

        let explained = analyze_default("[Obsolete(\"use New\")]\nclass Old\n{\n}\n");
        assert_eq!(with_key(&explained, "csharpsquid:S1133").len(), 1);
        assert!(with_key(&explained, "csharpsquid:S1123").is_empty());

        let fresh = analyze_default("class Current\n{\n}\n");
        assert!(with_key(&fresh, "csharpsquid:S1133").is_empty());
    }

    #[test]
    fn s1309_tracks_suppressions_and_pragmas() {
        let attribute =
            analyze_default("[SuppressMessage(\"Category\", \"CheckId\")]\nclass A\n{\n}\n");
        assert_eq!(with_key(&attribute, "csharpsquid:S1309").len(), 1);

        let pragma =
            analyze_default("class A\n{\n#pragma warning disable CS1234\n    void M() { }\n}\n");
        assert_eq!(with_key(&pragma, "csharpsquid:S1309").len(), 1);

        let quiet = analyze_default("class A\n{\n    void M() { }\n}\n");
        assert!(with_key(&quiet, "csharpsquid:S1309").is_empty());
    }

    #[test]
    fn s1607_flags_ignored_tests() {
        let ignored = analyze_default(
            "[Fact(Ignore = \"broken\")]\nvoid T() { }\n"
                .replace("[Fact(Ignore = \"broken\")]", "[Ignore]")
                .as_str(),
        );
        assert_eq!(with_key(&ignored, "csharpsquid:S1607").len(), 1);

        let active = analyze_default("class Tests\n{\n    [Fact]\n    void T() { }\n}\n");
        assert!(with_key(&active, "csharpsquid:S1607").is_empty());
    }

    #[test]
    fn s3431_flags_expected_exception_attribute() {
        let report =
            analyze_default("[ExpectedException(typeof(System.Exception))]\nvoid T() { }\n");
        assert_eq!(with_key(&report, "csharpsquid:S3431").len(), 1);

        let clean = analyze_default("class Tests\n{\n    [Fact]\n    void T() { }\n}\n");
        assert!(with_key(&clean, "csharpsquid:S3431").is_empty());
    }

    #[test]
    fn s6513_requires_coverage_exclusion_reasons() {
        let bare = analyze_default("[ExcludeFromCodeCoverage]\nclass Generated\n{\n}\n");
        assert_eq!(with_key(&bare, "csharpsquid:S6513").len(), 1);

        let justified = analyze_default(
            "[ExcludeFromCodeCoverage(\"generated code\")]\nclass Generated\n{\n}\n",
        );
        assert!(with_key(&justified, "csharpsquid:S6513").is_empty());
    }

    #[test]
    fn s1210_requires_comparable_contracts() {
        let incomplete = analyze_default(
            "class Temp : IComparable<Temp>\n{\n    public int CompareTo(Temp other) => 0;\n}\n",
        );
        assert_eq!(with_key(&incomplete, "csharpsquid:S1210").len(), 1);

        let complete = analyze_default(
            "class Temp : IComparable<Temp>\n{\n    public int value;\n\n    public int CompareTo(Temp other) => value.CompareTo(other.value);\n\n    public override bool Equals(object obj) => obj is Temp other && value == other.value;\n\n    public static bool operator <(Temp a, Temp b) => a.value < b.value;\n\n    public static bool operator >(Temp a, Temp b) => a.value > b.value;\n}\n",
        );
        assert!(with_key(&complete, "csharpsquid:S1210").is_empty());
    }

    #[test]
    fn s1206_flags_lone_equals_or_gethashcode_overrides() {
        let lone_equals = analyze_default(
            "class C\n{\n    public override bool Equals(object obj) => true;\n}\n",
        );
        assert_eq!(with_key(&lone_equals, "csharpsquid:S1206").len(), 1);

        let paired = analyze_default(
            "class C\n{\n    public override bool Equals(object obj) => true;\n\n    public override int GetHashCode() => 7;\n}\n",
        );
        assert!(with_key(&paired, "csharpsquid:S1206").is_empty());
    }

    #[test]
    fn s2166_flags_exception_names_without_exception_bases() {
        let misnamed = analyze_default("class BoomException\n{\n}\n");
        assert_eq!(with_key(&misnamed, "csharpsquid:S2166").len(), 1);

        let proper = analyze_default("class BoomException : System.Exception\n{\n}\n");
        assert!(with_key(&proper, "csharpsquid:S2166").is_empty());
    }

    #[test]
    fn s4027_requires_standard_constructors() {
        let thin = analyze_default(
            "class BoomError : System.Exception\n{\n    public BoomError() { }\n}\n",
        );
        assert_eq!(with_key(&thin, "csharpsquid:S4027").len(), 1);

        let full = analyze_default(
            "class BoomError : System.Exception\n{\n    public BoomError() { }\n\n    public BoomError(string message) { }\n\n    public BoomError(string message, System.Exception inner) { }\n}\n",
        );
        assert!(with_key(&full, "csharpsquid:S4027").is_empty());
    }

    #[test]
    fn s3875_flags_operator_equals_on_classes_but_not_structs() {
        let class_form = analyze_default(
            "class Ref\n{\n    public static bool operator ==(Ref a, Ref b) => true;\n\n    public static bool operator !=(Ref a, Ref b) => false;\n}\n",
        );
        assert_eq!(with_key(&class_form, "csharpsquid:S3875").len(), 1);

        let struct_form = analyze_default(
            "struct Value\n{\n    public static bool operator ==(Value a, Value b) => true;\n\n    public static bool operator !=(Value a, Value b) => false;\n}\n",
        );
        assert!(with_key(&struct_form, "csharpsquid:S3875").is_empty());
    }

    #[test]
    fn s4050_requires_equality_operator_pairing() {
        let unpaired = analyze_default(
            "struct Value\n{\n    public static bool operator ==(Value a, Value b) => true;\n}\n",
        );
        assert_eq!(with_key(&unpaired, "csharpsquid:S4050").len(), 1);

        let paired = analyze_default(
            "struct Value\n{\n    public static bool operator ==(Value a, Value b) => true;\n\n    public static bool operator !=(Value a, Value b) => false;\n\n    public override bool Equals(object obj) => true;\n}\n",
        );
        assert!(with_key(&paired, "csharpsquid:S4050").is_empty());
    }

    #[test]
    fn s4069_requires_named_operator_alternatives() {
        let anonymous = analyze_default(
            "struct Money\n{\n    public static Money operator +(Money a, Money b) => a;\n}\n",
        );
        assert_eq!(with_key(&anonymous, "csharpsquid:S4069").len(), 1);

        let named = analyze_default(
            "struct Money\n{\n    public static Money operator +(Money a, Money b) => a;\n\n    public static Money Add(Money a, Money b) => a;\n}\n",
        );
        assert!(with_key(&named, "csharpsquid:S4069").is_empty());
    }

    #[test]
    fn s3877_flags_throws_from_special_methods() {
        let throwing = analyze_default(
            "class C\n{\n    public override string ToString()\n    {\n        throw new System.Exception();\n    }\n}\n",
        );
        assert_eq!(with_key(&throwing, "csharpsquid:S3877").len(), 1);

        let calm = analyze_default(
            "class C\n{\n    public override string ToString()\n    {\n        return nameof(C);\n    }\n}\n",
        );
        assert!(with_key(&calm, "csharpsquid:S3877").is_empty());
    }

    #[test]
    fn s2225_flags_null_returning_to_string() {
        let null_return = analyze_default(
            "class C\n{\n    public override string ToString()\n    {\n        return null;\n    }\n}\n",
        );
        assert_eq!(with_key(&null_return, "csharpsquid:S2225").len(), 1);

        let real_value = analyze_default(
            "class C\n{\n    public override string ToString()\n    {\n        return \"C\";\n    }\n}\n",
        );
        assert!(with_key(&real_value, "csharpsquid:S2225").is_empty());
    }

    #[test]
    fn s2328_flags_mutable_fields_in_gethashcode() {
        let poisoned = analyze_default(
            "class C\n{\n    private int moving;\n\n    private readonly int frozen;\n\n    public override int GetHashCode() => frozen + moving;\n}\n",
        );
        assert_eq!(with_key(&poisoned, "csharpsquid:S2328").len(), 1);

        let stable = analyze_default(
            "class C\n{\n    private readonly int frozen;\n\n    public override int GetHashCode() => frozen;\n}\n",
        );
        assert!(with_key(&stable, "csharpsquid:S2328").is_empty());
    }

    #[test]
    fn s3397_flags_base_equals_inside_equals_override() {
        let misuse = analyze_default(
            "class C\n{\n    public override bool Equals(object obj) => base.Equals(obj);\n}\n",
        );
        assert_eq!(with_key(&misuse, "csharpsquid:S3397").len(), 1);

        let proper = analyze_default(
            "class C\n{\n    public override bool Equals(object obj) => obj is C other && other.id == id;\n\n    private int id;\n}\n",
        );
        assert!(with_key(&proper, "csharpsquid:S3397").is_empty());
    }

    #[test]
    fn s3249_flags_base_calls_on_object_derived_types() {
        let direct = analyze_default(
            "class C\n{\n    public override int GetHashCode() => base.GetHashCode();\n}\n",
        );
        assert_eq!(with_key(&direct, "csharpsquid:S3249").len(), 1);

        let derived = analyze_default(
            "class D : IEquatable<D>\n{\n    public bool Equals(D other) => true;\n\n    public override int GetHashCode() => base.GetHashCode();\n}\n",
        );
        assert!(with_key(&derived, "csharpsquid:S3249").is_empty());
    }

    #[test]
    fn s3897_flags_typed_equals_without_iequatable() {
        let undeclared =
            analyze_default("class C\n{\n    public bool Equals(C other) => true;\n}\n");
        assert_eq!(with_key(&undeclared, "csharpsquid:S3897").len(), 1);

        let declared = analyze_default(
            "class C : IEquatable<C>\n{\n    public bool Equals(C other) => true;\n}\n",
        );
        assert!(with_key(&declared, "csharpsquid:S3897").is_empty());
    }

    #[test]
    fn s3898_flags_structs_without_iequatable() {
        let boxed = analyze_default("struct Plain\n{\n    public int Value;\n}\n");
        assert_eq!(with_key(&boxed, "csharpsquid:S3898").len(), 1);

        let equatable = analyze_default(
            "struct Plain : IEquatable<Plain>\n{\n    public int Value;\n\n    public bool Equals(Plain other) => Value == other.Value;\n}\n",
        );
        assert!(with_key(&equatable, "csharpsquid:S3898").is_empty());
    }

    #[test]
    fn s3971_and_s3234_track_suppress_finalize_calls() {
        let finalizerless = analyze_default(
            "class C\n{\n    void Close()\n    {\n        System.GC.SuppressFinalize(this);\n    }\n}\n",
        );
        assert_eq!(with_key(&finalizerless, "csharpsquid:S3971").len(), 1);
        assert_eq!(with_key(&finalizerless, "csharpsquid:S3234").len(), 1);

        let with_finalizer = analyze_default(
            "class C\n{\n    ~C() { }\n\n    void Close()\n    {\n        System.GC.SuppressFinalize(this);\n    }\n}\n",
        );
        assert_eq!(with_key(&with_finalizer, "csharpsquid:S3971").len(), 1);
        assert!(with_key(&with_finalizer, "csharpsquid:S3234").is_empty());
    }

    // -----------------------------------------------------------------
    // A8 — member/API contracts
    // -----------------------------------------------------------------

    #[test]
    fn s1215_flags_gc_collect_calls() {
        let report = analyze_default(
            "class C\n{\n    void Clean()\n    {\n        System.GC.Collect();\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1215").len(), 1);

        let clean = analyze_default(
            "class C\n{\n    void Clean()\n    {\n        System.GC.KeepAlive(this);\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S1215").is_empty());
    }

    #[test]
    fn s1147_flags_exit_calls() {
        let report = analyze_default(
            "class C\n{\n    void Bail()\n    {\n        Environment.Exit(1);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1147").len(), 1);

        let clean = analyze_default(
            "class C\n{\n    void Bail()\n    {\n        Shutdown.Now();\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S1147").is_empty());
    }

    #[test]
    fn s106_flags_console_writes() {
        let report = analyze_default(
            "class C\n{\n    void Talk()\n    {\n        Console.WriteLine(\"hi\");\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S106").len(), 1);

        let clean = analyze_default(
            "class C\n{\n    void Talk()\n    {\n        Log.WriteLine(\"hi\");\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S106").is_empty());
    }

    #[test]
    fn s2925_flags_thread_sleep_only_in_tests() {
        let test = analyze_default(
            "class Checks\n{\n    [Fact]\n    void Waits()\n    {\n        Thread.Sleep(10);\n    }\n}\n",
        );
        assert_eq!(with_key(&test, "csharpsquid:S2925").len(), 1);

        let production = analyze_default(
            "class Service\n{\n    void Waits()\n    {\n        Thread.Sleep(10);\n    }\n}\n",
        );
        assert!(with_key(&production, "csharpsquid:S2925").is_empty());
    }

    #[test]
    fn s3889_flags_thread_suspend_resume() {
        let report = analyze_default(
            "class C\n{\n    void Pause(Thread workerThread)\n    {\n        workerThread.Suspend();\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3889").len(), 1);

        let clean = analyze_default(
            "class C\n{\n    void Pause(Thread worker)\n    {\n        worker.Join();\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S3889").is_empty());
    }

    #[test]
    fn s3869_flags_dangerous_handle_reads() {
        let report = analyze_default(
            "class C\n{\n    IntPtr Leak(SafeHandle mySafeHandle)\n    {\n        return mySafeHandle.DangerousGetHandle();\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3869").len(), 1);

        let clean = analyze_default(
            "class C\n{\n    IntPtr Peek(SafeHandle handle)\n    {\n        return handle.DangerousAddRef();\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S3869").is_empty());
    }

    #[test]
    fn s3884_flags_com_security_invocations() {
        let report = analyze_default(
            "class C\n{\n    void Harden()\n    {\n        CoSetProxyBlanket(null, 0, 0, null, 0, 0, IntPtr.Zero, 0);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3884").len(), 1);

        let clean = analyze_default(
            "class C\n{\n    void Harden()\n    {\n        CoSetProxyBlanketSafely();\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S3884").is_empty());
    }

    #[test]
    fn s3885_flags_assembly_load_from() {
        let report = analyze_default(
            "class Loader\n{\n    void Fetch(string path)\n    {\n        Assembly.LoadFrom(path);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3885").len(), 1);

        let clean = analyze_default(
            "class Loader\n{\n    void Fetch(string path)\n    {\n        Assembly.Load(path);\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S3885").is_empty());
    }

    #[test]
    fn s3902_flags_get_executing_assembly() {
        let report = analyze_default(
            "class C\n{\n    void Who()\n    {\n        Assembly.GetExecutingAssembly();\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3902").len(), 1);

        let clean = analyze_default(
            "class C\n{\n    void Who()\n    {\n        Assembly.GetCallingAssembly();\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S3902").is_empty());
    }

    #[test]
    fn s3216_requires_configure_await_false() {
        let blocking_context = analyze_default(
            "class C\n{\n    void Wait(Task task)\n    {\n        task.ConfigureAwait(true);\n    }\n}\n",
        );
        assert_eq!(with_key(&blocking_context, "csharpsquid:S3216").len(), 1);

        let off_context = analyze_default(
            "class C\n{\n    void Wait(Task task)\n    {\n        task.ConfigureAwait(false);\n    }\n}\n",
        );
        assert!(with_key(&off_context, "csharpsquid:S3216").is_empty());
    }

    #[test]
    fn s4462_flags_all_blocking_shapes() {
        let report = analyze_default(
            "class C\n{\n    void Block(Task task)\n    {\n        var v = task.Result;\n        task.Wait();\n        task.GetAwaiter().GetResult();\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S4462").len(), 3);

        let clean = analyze_default(
            "class C\n{\n    async System.Threading.Tasks.Task Await(Task task)\n    {\n        await task;\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S4462").is_empty());
    }

    #[test]
    fn s3169_flags_stacked_orderings() {
        let report = analyze_default(
            "class C\n{\n    void Sort(System.Collections.Generic.List<int> items)\n    {\n        items.OrderBy(a => a).OrderBy(b => -b);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3169").len(), 1);

        let single = analyze_default(
            "class C\n{\n    void Sort(System.Collections.Generic.List<int> items)\n    {\n        items.OrderBy(a => a);\n    }\n}\n",
        );
        assert!(with_key(&single, "csharpsquid:S3169").is_empty());
    }

    #[test]
    fn s6607_flags_filtering_after_ordering() {
        let late_filter = analyze_default(
            "class C\n{\n    void Query(System.Collections.Generic.List<int> items)\n    {\n        items.Where(v => v > 0).OrderBy(v => v);\n    }\n}\n",
        );
        assert_eq!(with_key(&late_filter, "csharpsquid:S6607").len(), 1);

        let early_filter = analyze_default(
            "class C\n{\n    void Query(System.Collections.Generic.List<int> items)\n    {\n        items.OrderBy(v => v).Where(v => v > 0);\n    }\n}\n",
        );
        assert!(with_key(&early_filter, "csharpsquid:S6607").is_empty());
    }

    #[test]
    fn s2971_flags_where_terminal_chains() {
        let report = analyze_default(
            "class C\n{\n    bool Any(System.Collections.Generic.List<int> items)\n    {\n        return items.Where(v => v > 0).Any();\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2971").len(), 1);

        let clean = analyze_default(
            "class C\n{\n    bool Any(System.Collections.Generic.List<int> items)\n    {\n        return items.Any();\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S2971").is_empty());
    }

    #[test]
    fn s3267_flags_conditionally_appending_loops() {
        let report = analyze_default(
            "class C\n{\n    void Gather(int[] items, System.Collections.Generic.List<int> result)\n    {\n        foreach (var item in items)\n        {\n            if (item > 0)\n            {\n                result.Add(item);\n            }\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3267").len(), 1);

        let complex = analyze_default(
            "class C\n{\n    void Gather(int[] items, System.Collections.Generic.List<int> result)\n    {\n        foreach (var item in items)\n        {\n            if (item > 0)\n            {\n                result.Add(item);\n            }\n            else\n            {\n                result.Add(-item);\n            }\n        }\n    }\n}\n",
        );
        assert!(with_key(&complex, "csharpsquid:S3267").is_empty());
    }

    #[test]
    fn s4635_flags_zero_based_substrings() {
        let report = analyze_default(
            "class C\n{\n    string Head(string s)\n    {\n        return s.Substring(0, 3);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S4635").len(), 1);

        let offset = analyze_default(
            "class C\n{\n    string Head(string s)\n    {\n        return s.Substring(1, 3);\n    }\n}\n",
        );
        assert!(with_key(&offset, "csharpsquid:S4635").is_empty());
    }

    #[test]
    fn s6610_flags_single_character_string_arguments() {
        let report = analyze_default(
            "class C\n{\n    bool Starts(string s)\n    {\n        return s.StartsWith(\"a\");\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S6610").len(), 1);

        let longer = analyze_default(
            "class C\n{\n    bool Starts(string s)\n    {\n        return s.StartsWith(\"ab\");\n    }\n}\n",
        );
        assert!(with_key(&longer, "csharpsquid:S6610").is_empty());
    }

    #[test]
    fn s6617_flags_any_with_parameter_equality_lambda() {
        let report = analyze_default(
            "class C\n{\n    bool Has(System.Collections.Generic.List<int> items)\n    {\n        return items.Any(v => v == 1);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S6617").len(), 1);

        let predicate = analyze_default(
            "class C\n{\n    bool Has(System.Collections.Generic.List<int> items)\n    {\n        return items.All(v => v > 0);\n    }\n}\n",
        );
        assert!(with_key(&predicate, "csharpsquid:S6617").is_empty());
    }

    #[test]
    fn s6612_requires_concurrent_dictionary_delegates() {
        let eager = analyze_default(
            "class C\n{\n    int Value(System.Collections.Concurrent.ConcurrentDictionary<int, int> map)\n    {\n        return map.GetOrAdd(1, ExpensiveBuild());\n    }\n}\n",
        );
        assert_eq!(with_key(&eager, "csharpsquid:S6612").len(), 1);

        let lazy = analyze_default(
            "class C\n{\n    int Value(System.Collections.Concurrent.ConcurrentDictionary<int, int> map)\n    {\n        return map.GetOrAdd(1, key => Build(key));\n    }\n}\n",
        );
        assert!(with_key(&lazy, "csharpsquid:S6612").is_empty());
    }

    #[test]
    fn s6618_flags_formattable_string_flows() {
        let report = analyze_default(
            "class C\n{\n    string Text()\n    {\n        return FormattableString.Invariant($\"x{1}\");\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S6618").len(), 1);

        let clean = analyze_default(
            "class C\n{\n    string Text()\n    {\n        return string.Format(\"x{0}\", 1);\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S6618").is_empty());
    }

    #[test]
    fn s3456_flags_string_array_conversions() {
        let indexed = analyze_default(
            "class C\n{\n    char First(string s)\n    {\n        return s.ToCharArray()[0];\n    }\n}\n",
        );
        assert_eq!(with_key(&indexed, "csharpsquid:S3456").len(), 1);

        let iterated = analyze_default(
            "class C\n{\n    void Walk(string s)\n    {\n        foreach (char c in s.ToCharArray())\n        {\n            Use(c);\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&iterated, "csharpsquid:S3456").len(), 1);

        let direct = analyze_default(
            "class C\n{\n    void Walk(string s)\n    {\n        foreach (char c in s)\n        {\n            Use(c);\n        }\n    }\n}\n",
        );
        assert!(with_key(&direct, "csharpsquid:S3456").is_empty());
    }

    #[test]
    fn s1643_flags_string_concatenation_inside_loops() {
        let looping = analyze_default(
            "class C\n{\n    string Build()\n    {\n        var text = \"\";\n        while (More())\n        {\n            text += \",\";\n        }\n        return text;\n    }\n}\n",
        );
        assert_eq!(with_key(&looping, "csharpsquid:S1643").len(), 1);

        let outside = analyze_default(
            "class C\n{\n    string Build()\n    {\n        var text = \"a\";\n        text += \"b\";\n        return text;\n    }\n}\n",
        );
        assert!(with_key(&outside, "csharpsquid:S1643").is_empty());

        let numeric = analyze_default(
            "class C\n{\n    int Count(int total)\n    {\n        while (More())\n        {\n            total += 1;\n        }\n        return total;\n    }\n}\n",
        );
        assert!(with_key(&numeric, "csharpsquid:S1643").is_empty());
    }
    #[test]
    fn s1192_flags_repeated_literals_from_the_second_occurrence() {
        let repeated = analyze_default(
            "class C\n{\n    void M()\n    {\n        Use(\"alpha\");\n        Use(\"alpha\");\n\
             Use(\"alpha\");\n        Use(\"beta\");\n        Use(\"beta\");\n    }\n}\n",
        );
        let flagged = with_key(&repeated, "csharpsquid:S1192");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 6);
        assert_eq!(flagged[1].range.start.line, 7);
        assert!(flagged[0].message.contains("\"alpha\" 3 times."));

        let options = AnalyzerOptions {
            duplicate_string_threshold: 2,
            ..Default::default()
        };
        let lowered = analyze_options(
            "class C\n{\n    void M()\n    {\n        Use(\"beta\");\n        Use(\"beta\");\n    }\n}\n",
            &options,
        );
        assert_eq!(with_key(&lowered, "csharpsquid:S1192").len(), 1);
    }

    #[test]
    fn s1192_exempts_empty_and_unique_literals() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        Use(\"\");\n        Use(\"\");\n\
             Use(\"\");\n        Use(\"only once\");\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1192").is_empty());
    }

    #[test]
    fn s2068_flags_credential_named_assignments_and_declarators() {
        let report = analyze_default(
            "class C\n{\n    string pwd = \"s3cret\";\n\n    void Set()\n    {\n\
                 password = \"hunter2\";\n        this.passPhrase = \"z\";\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2068");
        assert_eq!(flagged.len(), 3);
        assert!(flagged[0].message.contains("pwd"));

        let clean = analyze_default(
            "class C\n{\n    string name = \"s3cret\";\n\n    void Set()\n    {\n\
                 password = string.Empty;\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S2068").is_empty());
    }

    #[test]
    fn s6418_needs_secret_word_and_entropy_together() {
        let secret = analyze_default("var apiKey = \"aB3$xY9#kQ\";\n");
        assert_eq!(with_key(&secret, "csharpsquid:S6418").len(), 1);

        let low_entropy = analyze_default("var token = \"abc12345\";\n");
        assert!(with_key(&low_entropy, "csharpsquid:S6418").is_empty());

        let no_secret_word = analyze_default("var label = \"aB3$xY9#kQ\";\n");
        assert!(with_key(&no_secret_word, "csharpsquid:S6418").is_empty());

        let dashed = analyze_default("var My_ApiKey = \"aB3$xY9#kQ\";\n");
        assert_eq!(with_key(&dashed, "csharpsquid:S6418").len(), 1);
    }

    #[test]
    fn s1313_flags_only_valid_dotted_quads() {
        let report = analyze_default(
            "class C\n{\n    string ip = \"192.168.0.1\";\n    string bad = \"999.9.9.9\";\n\
                 string short1 = \"1.2.3\";\n    string ver = \"v1.2.3.4\";\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1313");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s1075_flags_scheme_prefixed_literals() {
        let report = analyze_default(
            "class C\n{\n    string a = \"https://example.com/x\";\n    string b = \"example.com/y\";\n\
                 string c = \"FTP://f.z\";\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1075").len(), 2);
    }

    #[test]
    fn s2857_flags_squeezed_sql_keywords_only() {
        let squeezed = analyze_default("var q = \"SELECT*FROM users WHERE id=@id\";\n");
        let flagged = with_key(&squeezed, "csharpsquid:S2857");
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].message.contains("'SELECT'"));

        let spaced = analyze_default("var q = \"SELECT * FROM users\";\n");
        assert!(with_key(&spaced, "csharpsquid:S2857").is_empty());

        let wordy = analyze_default("var w = \"SELECTION of items\";\n");
        assert!(with_key(&wordy, "csharpsquid:S2857").is_empty());
    }

    #[test]
    fn s5856_rejects_syntactically_invalid_patterns() {
        let report = analyze_default(
            "class C\n{\n    Regex R = new Regex(\"[a-z+\");\n\n    bool Check(string input) =>\n\
                 Regex.IsMatch(input, \"*bad\");\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S5856").len(), 2);

        let valid = analyze_default(
            "class C\n{\n    Regex R = new Regex(@\"^\\d{2,4}([a-z]|$)\", RegexOptions.Compiled);\n\
                 bool Look(string input) => Regex.IsMatch(input, \"(?<=x)y*\");\n}\n",
        );
        assert!(with_key(&valid, "csharpsquid:S5856").is_empty());

        let reversed = analyze_default("bool B = Regex.IsMatch(s, \"[z-a]\");\n");
        assert_eq!(with_key(&reversed, "csharpsquid:S5856").len(), 1);
    }

    #[test]
    fn s6444_requires_timeouts_on_regex_apis() {
        let missing = analyze_default(
            "class C\n{\n    Regex R = new Regex(\"p\");\n\n    bool Find(string input) =>\n\
                 Regex.IsMatch(input, \"\\\\w\");\n}\n",
        );
        assert_eq!(with_key(&missing, "csharpsquid:S6444").len(), 2);

        let present = analyze_default(
            "class C\n{\n    Regex R = new Regex(\n        \"p\",\n\
                 RegexOptions.None,\n        TimeSpan.FromSeconds(2));\n\n    bool Find(string input) =>\n\
                 Regex.IsMatch(input, \"\\\\w\", RegexOptions.None, TimeSpan.FromSeconds(2));\n}\n",
        );
        assert!(with_key(&present, "csharpsquid:S6444").is_empty());
    }

    #[test]
    fn s2479_flags_raw_whitespace_but_not_escapes() {
        let raw_tab = analyze_default("var t = \"a\tb\";\n");
        assert_eq!(with_key(&raw_tab, "csharpsquid:S2479").len(), 1);

        let escaped = analyze_default("var t = \"a\\tb\\n\";\n");
        assert!(with_key(&escaped, "csharpsquid:S2479").is_empty());
    }

    #[test]
    fn s818_flags_lowercase_numeric_suffixes() {
        let flagged = analyze_default(
            "class C\n{\n    long a = 123l;\n    float b = 1.5f;\n    decimal c = 100m;\n}\n",
        );
        assert_eq!(with_key(&flagged, "csharpsquid:S818").len(), 3);

        let clean = analyze_default(
            "class C\n{\n    long a = 123L;\n    double b = 1.5D;\n    ulong c = 0xFFUL;\n\
                 int d = 0xd;\n    int e = 42;\n    double f = 1.5e3;\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S818").is_empty());
    }

    #[test]
    fn s1128_flags_using_directives_without_file_references() {
        let unused = analyze_default("using System.Collections.Generic;\nclass C\n{\n}\n");
        let flagged = with_key(&unused, "csharpsquid:S1128");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);

        let aliased = analyze_default(
            "using Alias = System.IO.File;\nclass C\n{\n    string Read()\n    {\n\
                 return File.ReadAllText(\"x\");\n    }\n}\n",
        );
        assert!(with_key(&aliased, "csharpsquid:S1128").is_empty());

        let static_unused = analyze_default("using static System.Math;\nclass C\n{\n}\n");
        assert_eq!(with_key(&static_unused, "csharpsquid:S1128").len(), 1);
    }

    #[test]
    fn s1144_flags_unreferenced_private_members_only() {
        let unused =
            analyze_default("class C\n{\n    int field;\n\n    void Method()\n    {\n    }\n}\n");
        assert_eq!(with_key(&unused, "csharpsquid:S1144").len(), 2);

        let overloads = analyze_default(
            "class C\n{\n    void Twice()\n    {\n    }\n\n    void Twice(int n)\n    {\n    }\n}\n",
        );
        assert_eq!(with_key(&overloads, "csharpsquid:S1144").len(), 2);

        let used = analyze_default(
            "class C\n{\n    int field;\n\n    public int Get()\n    {\n\
                 return field;\n    }\n}\n",
        );
        assert!(with_key(&used, "csharpsquid:S1144").is_empty());

        let partial = analyze_default("partial class C\n{\n    void Method()\n    {\n    }\n}\n");
        assert!(with_key(&partial, "csharpsquid:S1144").is_empty());

        let constant = analyze_default("class C\n{\n    const int Limit = 5;\n}\n");
        assert!(with_key(&constant, "csharpsquid:S1144").is_empty());
    }

    #[test]
    fn s1481_flags_locals_nobody_reads() {
        let stale = analyze_default(
            "class C\n{\n    int M()\n    {\n        int stale = 1;\n        return 2;\n    }\n}\n",
        );
        assert_eq!(with_key(&stale, "csharpsquid:S1481").len(), 1);

        let read = analyze_default(
            "class C\n{\n    int M()\n    {\n        int fresh = 1;\n        return fresh;\n    }\n}\n",
        );
        assert!(with_key(&read, "csharpsquid:S1481").is_empty());

        let exempt = analyze_default(
            "class C\n{\n    void M()\n    {\n        int _ = 1;\n        const int kMax = 5;\n\
                 Use(kMax);\n    }\n}\n",
        );
        assert!(with_key(&exempt, "csharpsquid:S1481").is_empty());
    }

    #[test]
    fn s1172_flags_parameters_no_body_reads() {
        let unused = analyze_default(
            "class C\n{\n    void Handle(int value)\n    {\n        Log();\n    }\n}\n",
        );
        let flagged = with_key(&unused, "csharpsquid:S1172");
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].message.contains("'value'"));

        let read = analyze_default(
            "class C\n{\n    void Handle(int value)\n    {\n        Log(value);\n    }\n}\n",
        );
        assert!(with_key(&read, "csharpsquid:S1172").is_empty());

        let visible = analyze_default(
            "class C\n{\n    public void Handle(int value)\n    {\n        Log();\n    }\n}\n",
        );
        assert!(with_key(&visible, "csharpsquid:S1172").is_empty());

        let discarded = analyze_default(
            "class C\n{\n    void Handle(int _)\n    {\n        Log();\n    }\n}\n",
        );
        assert!(with_key(&discarded, "csharpsquid:S1172").is_empty());
    }

    #[test]
    fn s109_flags_numbers_beyond_the_small_allowance() {
        let magic =
            analyze_default("class C\n{\n    int M()\n    {\n        return 42;\n    }\n}\n");
        assert_eq!(with_key(&magic, "csharpsquid:S109").len(), 1);

        let hex = analyze_default("int mask = 0xFF;\n");
        assert_eq!(with_key(&hex, "csharpsquid:S109").len(), 1);

        let boundary_two = analyze_default("int x = 2;\n");
        assert_eq!(with_key(&boundary_two, "csharpsquid:S109").len(), 1);

        let allowed = analyze_default("int a = -1;\nint b = 0;\nint c = 1;\ndouble d = 1.0;\n");
        assert!(with_key(&allowed, "csharpsquid:S109").is_empty());

        let constants = analyze_default(
            "class C\n{\n    const int Limit = 100;\n    int Read() => Limit;\n}\n",
        );
        assert!(with_key(&constants, "csharpsquid:S109").is_empty());

        let enumerations = analyze_default("enum E\n{\n    Max = 200,\n}\n");
        assert!(with_key(&enumerations, "csharpsquid:S109").is_empty());

        let defaults = analyze_default(
            "class C\n{\n    void M(int retries = 3)\n    {\n        Use(retries);\n    }\n}\n",
        );
        assert!(with_key(&defaults, "csharpsquid:S109").is_empty());
    }

    #[test]
    fn s3264_flags_events_that_are_never_raised() {
        let silent = analyze_default("class C\n{\n    event System.EventHandler Done;\n}\n");
        let flagged = with_key(&silent, "csharpsquid:S3264");
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].message.contains("'Done'"));

        let raised = analyze_default(
            "class C\n{\n    event System.EventHandler Done;\n\n    void Raise()\n    {\n        Done(this, System.EventArgs.Empty);\n    }\n}\n",
        );
        assert!(with_key(&raised, "csharpsquid:S3264").is_empty());

        // Documented heuristic limit: a bare subscription silences the check,
        // because distinguishing it from a raise needs type flow.
        let subscribed = analyze_default(
            "class C\n{\n    event System.EventHandler Done;\n\n    void Wire()\n    {\n        Done += OnDone;\n    }\n}\n",
        );
        assert!(with_key(&subscribed, "csharpsquid:S3264").is_empty());
    }

    #[test]
    fn s3251_flags_partial_methods_without_implementations() {
        let orphan = analyze_default("partial class C\n{\n    partial void OnRaise();\n}\n");
        for f in &orphan.issues {
            println!("DBGA {}", f.rule_key);
        }
        let flagged = with_key(&orphan, "csharpsquid:S3251");
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].message.contains("'OnRaise'"));

        let paired = analyze_default(
            "partial class C\n{\n    partial void OnRaise();\n\n    partial void OnRaise()\n    {\n    }\n}\n",
        );
        assert!(with_key(&paired, "csharpsquid:S3251").is_empty());

        // Boundary: without the 'partial' modifier the method is out of scope.
        let plain = analyze_default("class C\n{\n    void Method();\n}\n");
        assert!(with_key(&plain, "csharpsquid:S3251").is_empty());
    }

    #[test]
    fn s3253_flags_redundant_constructors_and_finalizers() {
        let redundant = analyze_default(
            "class C\n{\n    public C()\n    {\n    }\n\n    ~C()\n    {\n        base.Dispose();\n    }\n}\n",
        );
        assert_eq!(with_key(&redundant, "csharpsquid:S3253").len(), 2);

        let meaningful = analyze_default(
            "class C\n{\n    private C()\n    {\n    }\n\n    public C(int seed)\n    {\n        Use(seed);\n    }\n\n    ~C()\n    {\n        Log();\n    }\n}\n",
        );
        assert!(with_key(&meaningful, "csharpsquid:S3253").is_empty());
    }

    #[test]
    fn s3052_flags_field_initializers_spelling_defaults() {
        let defaults = analyze_default(
            "class C\n{\n    int a = 0;\n    string b = null;\n    bool c = false;\n        char d = '\\0';\n    double e = 0.0;\n    object f = default;\n}\n",
        );
        assert_eq!(with_key(&defaults, "csharpsquid:S3052").len(), 6);

        let meaningful = analyze_default(
            "class C\n{\n    int a = 1;\n    string b = \"x\";\n    bool c = true;\n        double d = 0.5;\n    int[] e = new int[0];\n}\n",
        );
        assert!(with_key(&meaningful, "csharpsquid:S3052").is_empty());
    }

    #[test]
    fn s3962_promotes_literal_backed_static_readonly_fields() {
        let literal =
            analyze_default("class C\n{\n    static readonly string Greeting = \"hi\";\n}\n");
        assert_eq!(with_key(&literal, "csharpsquid:S3962").len(), 1);

        let computed = analyze_default(
            "class C\n{\n    static readonly TimeSpan Wait = TimeSpan.FromSeconds(2);\n        readonly int local = 5;\n}\n",
        );
        assert!(with_key(&computed, "csharpsquid:S3962").is_empty());
    }

    #[test]
    fn s3963_moves_static_ctor_only_initialization_inline() {
        let moved = analyze_default(
            "class C\n{\n    static int value;\n\n    static C()\n    {\n        value = Compute();\n    }\n}\n",
        );
        let flagged = with_key(&moved, "csharpsquid:S3963");
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].message.contains("'value'"));

        let inline = analyze_default(
            "class C\n{\n    static int value = Compute();\n\n    static C()\n    {\n        value++;\n    }\n}\n",
        );
        assert!(with_key(&inline, "csharpsquid:S3963").is_empty());

        let untouched = analyze_default(
            "class C\n{\n    static int value;\n\n    static C()\n    {\n        Log();\n    }\n}\n",
        );
        assert!(with_key(&untouched, "csharpsquid:S3963").is_empty());
    }

    #[test]
    fn s3010_flags_static_writes_from_instance_constructors() {
        let leaking = analyze_default(
            "class C\n{\n    static int count;\n    int seen;\n\n    public C()\n    {\n        count = 1;\n        seen = 2;\n    }\n}\n",
        );
        let flagged = with_key(&leaking, "csharpsquid:S3010");
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].message.contains("'count'"));

        let proper = analyze_default(
            "class C\n{\n    static int count;\n\n    static C()\n    {\n        count = 1;\n    }\n        public C()\n    {\n        Use(count);\n    }\n}\n",
        );
        assert!(with_key(&proper, "csharpsquid:S3010").is_empty());
    }

    #[test]
    fn s2996_flags_thread_static_field_initializers() {
        let initialized =
            analyze_default("class C\n{\n    [ThreadStatic]\n    static int perThread = 5;\n}\n");
        assert_eq!(with_key(&initialized, "csharpsquid:S2996").len(), 1);

        let bare =
            analyze_default("class C\n{\n    [ThreadStatic]\n    static int perThread;\n}\n");
        assert!(with_key(&bare, "csharpsquid:S2996").is_empty());
    }

    #[test]
    fn s3005_requires_static_on_thread_static_fields() {
        let instance = analyze_default("class C\n{\n    [ThreadStatic]\n    int perThread;\n}\n");
        let flagged = with_key(&instance, "csharpsquid:S3005");
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].message.contains("'static'"));

        let proper =
            analyze_default("class C\n{\n    [ThreadStatic]\n    static int perThread;\n}\n");
        assert!(with_key(&proper, "csharpsquid:S3005").is_empty());
    }

    #[test]
    fn s2743_flags_static_fields_inside_generic_types() {
        let shared =
            analyze_default("class Cache<T>\n{\n    static Dictionary<string, T> map;\n}\n");
        let flagged = with_key(&shared, "csharpsquid:S2743");
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].message.contains("'map'"));

        let instance_only = analyze_default(
            "class Cache<T>\n{\n    Dictionary<string, T> map;\n\n    const int Limit = 4;\n}\n",
        );
        assert!(with_key(&instance_only, "csharpsquid:S2743").is_empty());

        let non_generic = analyze_default("class Cache\n{\n    static int hits;\n}\n");
        assert!(with_key(&non_generic, "csharpsquid:S2743").is_empty());
    }

    #[test]
    fn s3906_keeps_event_handler_delegates_void() {
        let returning = analyze_default("delegate int Op(object sender, MyEventArgs e);\n");
        for f in &returning.issues {
            println!("DBGB {}", f.rule_key);
        }
        let flagged = with_key(&returning, "csharpsquid:S3906");
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].message.contains("'void'"));

        let proper = analyze_default("delegate void Op(object sender, MyEventArgs e);\n");
        assert!(with_key(&proper, "csharpsquid:S3906").is_empty());

        let unshaped = analyze_default("delegate int Map(string input);\n");
        assert!(with_key(&unshaped, "csharpsquid:S3906").is_empty());
    }

    #[test]
    fn s3908_prefers_event_handler_over_custom_shaped_delegates() {
        let custom = analyze_default(
            "delegate void Op(object sender, MyEventArgs e);\n\nclass C\n{\n    event Op Raised;\n}\n",
        );
        let flagged = with_key(&custom, "csharpsquid:S3908");
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].message.contains("'Raised'"));

        let framework =
            analyze_default("class C\n{\n    event System.EventHandler<MyEventArgs> Raised;\n}\n");
        assert!(with_key(&framework, "csharpsquid:S3908").is_empty());

        let unshaped =
            analyze_default("delegate void Op(int code);\n\nclass C\n{\n    event Op Failed;\n}\n");
        assert!(with_key(&unshaped, "csharpsquid:S3908").is_empty());
    }

    #[test]
    fn s4225_flags_extension_methods_on_object() {
        let broad = analyze_default(
            "static class Ext\n{\n    public static bool Blank(this object item)\n    {\n        return item == null;\n    }\n}\n",
        );
        let flagged = with_key(&broad, "csharpsquid:S4225");
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].message.contains("'object'"));

        let specific = analyze_default(
            "static class Ext\n{\n    public static bool Blank(this string item)\n    {\n        return item == null;\n    }\n}\n",
        );
        assert!(with_key(&specific, "csharpsquid:S4225").is_empty());

        let plain_method = analyze_default(
            "static class Ext\n{\n    public static bool Blank(object item)\n    {\n        return item == null;\n    }\n}\n",
        );
        assert!(with_key(&plain_method, "csharpsquid:S4225").is_empty());
    }

    #[test]
    fn s4220_flags_events_without_eventargs_payloads() {
        let raw_payload = analyze_default(
            "delegate void Handler(int code);\n\nclass C\n{\n    event Handler Failed;\n}\n",
        );
        let flagged = with_key(&raw_payload, "csharpsquid:S4220");
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].message.contains("'Failed'"));

        let proper = analyze_default(
            "delegate void Handler(object sender, MyEventArgs e);\n\nclass C\n{\n        event Handler Failed;\n}\n",
        );
        assert!(with_key(&proper, "csharpsquid:S4220").is_empty());

        let framework = analyze_default("class C\n{\n    event System.EventHandler Failed;\n}\n");
        assert!(with_key(&framework, "csharpsquid:S4220").is_empty());
    }

    #[test]
    fn s3993_constrains_attribute_classes_with_usage() {
        let open = analyze_default("class Mine : System.Attribute\n{\n}\n");
        let flagged = with_key(&open, "csharpsquid:S3993");
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].message.contains("[AttributeUsage]"));

        let constrained = analyze_default(
            "[System.AttributeUsage(System.AttributeTargets.Class)]\nclass Mine : System.Attribute\n{\n}\n",
        );
        assert!(with_key(&constrained, "csharpsquid:S3993").is_empty());

        let plain_class = analyze_default("class Mine : Base\n{\n}\n");
        assert!(with_key(&plain_class, "csharpsquid:S3993").is_empty());
    }

    #[test]
    fn s3990_s3992_s4026_flag_missing_assembly_annotations() {
        let partial = analyze_default("[assembly: System.ComVisible(true)]\nclass C\n{\n}\n");
        assert_eq!(with_key(&partial, "csharpsquid:S3990").len(), 1);
        assert!(with_key(&partial, "csharpsquid:S3992").is_empty());
        assert_eq!(with_key(&partial, "csharpsquid:S4026").len(), 1);

        let complete = analyze_default(
            "[assembly: System.CLSCompliant(false)]\n[assembly: System.ComVisible(false)]\n        [assembly: System.NeutralResourcesLanguage(\"en\")]\nclass C\n{\n}\n",
        );
        assert!(with_key(&complete, "csharpsquid:S3990").is_empty());
        assert!(with_key(&complete, "csharpsquid:S3992").is_empty());
        assert!(with_key(&complete, "csharpsquid:S4026").is_empty());

        // Boundary: files without any assembly attributes are not
        // assembly-info files and stay clean.
        let plain = analyze_default("class C\n{\n}\n");
        assert!(with_key(&plain, "csharpsquid:S3990").is_empty());
        assert!(with_key(&plain, "csharpsquid:S3992").is_empty());
        assert!(with_key(&plain, "csharpsquid:S4026").is_empty());
    }

    #[test]
    fn s4016_renames_reserved_enum_members() {
        let reserved = analyze_default("enum Level\n{\n    Reserved,\n    High = 1,\n}\n");
        let flagged = with_key(&reserved, "csharpsquid:S4016");
        assert_eq!(flagged.len(), 1);

        let lowercase = analyze_default("enum Level\n{\n    reserved,\n    High = 1,\n}\n");
        assert_eq!(with_key(&lowercase, "csharpsquid:S4016").len(), 1);

        let clean = analyze_default("enum Level\n{\n    Low,\n    High = 1,\n}\n");
        assert!(with_key(&clean, "csharpsquid:S4016").is_empty());
    }

    #[test]
    fn s4070_flags_unused_flags_enumerations() {
        let decorated_only =
            analyze_default("[System.Flags]\nenum Rights\n{\n    Read = 1,\n    Write = 2,\n}\n");
        let flagged = with_key(&decorated_only, "csharpsquid:S4070");
        assert_eq!(flagged.len(), 1);

        let combined = analyze_default(
            "[System.Flags]\nenum Rights\n{\n    Read = 1,\n    Write = 2,\n}\n\nclass C\n{\n        Rights All() => Rights.Read | Rights.Write;\n}\n",
        );
        assert!(with_key(&combined, "csharpsquid:S4070").is_empty());

        let undecorated = analyze_default("enum Rights\n{\n    Read = 1,\n    Write = 2,\n}\n");
        assert!(with_key(&undecorated, "csharpsquid:S4070").is_empty());
    }

    #[test]
    fn s2345_requires_explicit_values_on_flags_members() {
        let implicit_tail =
            analyze_default("[System.Flags]\nenum Rights\n{\n    Read = 1,\n    Write,\n}\n");
        let flagged = with_key(&implicit_tail, "csharpsquid:S2345");
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].message.contains("'Write'"));

        let explicit_all =
            analyze_default("[System.Flags]\nenum Rights\n{\n    Read = 1,\n    Write = 2,\n}\n");
        assert!(with_key(&explicit_all, "csharpsquid:S2345").is_empty());

        // Boundary: without '[Flags]' implicit numbering is fine.
        let sequential = analyze_default("enum Stage\n{\n    Start,\n    Stop,\n}\n");
        assert!(with_key(&sequential, "csharpsquid:S2345").is_empty());
    }

    #[test]
    fn s2346_names_the_zero_flags_member_none() {
        let misnamed_zero =
            analyze_default("[System.Flags]\nenum Rights\n{\n    Zero = 0,\n    Read = 1,\n}\n");
        let flagged = with_key(&misnamed_zero, "csharpsquid:S2346");
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].message.contains("'Zero'"));

        // Boundary: an uninitialized first member is implicitly zero and
        // equally needs the 'None' name.
        let implicit_zero =
            analyze_default("[System.Flags]\nenum Rights\n{\n    Read,\n    Write = 2,\n}\n");
        let flagged_implicit = with_key(&implicit_zero, "csharpsquid:S2346");
        assert_eq!(flagged_implicit.len(), 1);
        assert!(flagged_implicit[0].message.contains("'Read'"));

        // No zero-valued member at all: nothing to rename in-file.
        let no_zero =
            analyze_default("[System.Flags]\nenum Levels\n{\n    Read = 1,\n    Write = 2,\n}\n");
        assert!(with_key(&no_zero, "csharpsquid:S2346").is_empty());

        let named_none =
            analyze_default("[System.Flags]\nenum Rights\n{\n    None = 0,\n    Read = 1,\n}\n");
        assert!(with_key(&named_none, "csharpsquid:S2346").is_empty());
    }

    #[test]
    fn s3597_requires_service_contract_on_operation_methods() {
        let orphan =
            analyze_default("class Repo\n{\n    [OperationContract]\n    void Do(int x) { }\n}\n");
        let flagged = with_key(&orphan, "csharpsquid:S3597");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);

        let contracted = analyze_default(
            "[ServiceContract]\nclass Repo\n{\n    [OperationContract]\n    void Do(int x) { }\n}\n",
        );
        assert!(with_key(&contracted, "csharpsquid:S3597").is_empty());
    }

    #[test]
    fn s3598_flags_one_way_operations_returning_values() {
        let one_way_result = analyze_default(
            "[ServiceContract]\nclass Repo\n{\n    [OperationContract(IsOneWay = true)]\n    int Count(string q) => 1;\n}\n",
        );
        let flagged = with_key(&one_way_result, "csharpsquid:S3598");
        assert_eq!(flagged.len(), 1);

        // Boundary: a void operation may be one-way.
        let one_way_void = analyze_default(
            "[ServiceContract]\nclass Repo\n{\n    [OperationContract(IsOneWay = true)]\n    void Fire(string q) { }\n}\n",
        );
        assert!(with_key(&one_way_void, "csharpsquid:S3598").is_empty());

        // Boundary: without 'IsOneWay' returning is fine.
        let two_way = analyze_default(
            "[ServiceContract]\nclass Repo\n{\n    [OperationContract]\n    int Count(string q) => 1;\n}\n",
        );
        assert!(with_key(&two_way, "csharpsquid:S3598").is_empty());
    }

    #[test]
    fn s3603_flags_pure_void_methods() {
        let pure_void = analyze_default("class C\n{\n    [Pure]\n    void Save(int x) { }\n}\n");
        let flagged = with_key(&pure_void, "csharpsquid:S3603");
        assert_eq!(flagged.len(), 1);

        let pure_value = analyze_default("class C\n{\n    [Pure]\n    int Add(int x) => x;\n}\n");
        assert!(with_key(&pure_value, "csharpsquid:S3603").is_empty());
    }

    #[test]
    fn s4210_requires_stathread_on_winforms_entry_points() {
        let plain_main = analyze_default(
            "using System.Windows.Forms;\nclass Program\n{\n    static void Main() { }\n}\n",
        );
        let flagged = with_key(&plain_main, "csharpsquid:S4210");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 4);

        let decorated_main = analyze_default(
            "using System.Windows.Forms;\nclass Program\n{\n    [STAThread]\n    static void Main() { }\n}\n",
        );
        assert!(with_key(&decorated_main, "csharpsquid:S4210").is_empty());

        // Boundary: outside WinForms an unadorned 'Main' stays clean.
        let console_main = analyze_default("class Program\n{\n    static void Main() { }\n}\n");
        assert!(with_key(&console_main, "csharpsquid:S4210").is_empty());
    }

    #[test]
    fn s4211_flags_conflicting_transparency_annotations() {
        let both =
            analyze_default("[SecurityCritical]\n[SecuritySafeCritical]\nclass Vault\n{\n}\n");
        let flagged = with_key(&both, "csharpsquid:S4211");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);

        // Boundary: either level alone is consistent.
        let critical_only = analyze_default("[SecurityCritical]\nclass Vault\n{\n}\n");
        assert!(with_key(&critical_only, "csharpsquid:S4211").is_empty());
    }

    #[test]
    fn s4212_secures_serialization_constructors() {
        let public_ctor = analyze_default(
            "class Item\n{\n    public Item(SerializationInfo info, StreamingContext ctx) { }\n}\n",
        );
        let flagged = with_key(&public_ctor, "csharpsquid:S4212");
        assert_eq!(flagged.len(), 1);

        // Boundary: protected serialization constructors are the convention.
        let protected_ctor = analyze_default(
            "class Item\n{\n    protected Item(SerializationInfo info, StreamingContext ctx) { }\n}\n",
        );
        assert!(with_key(&protected_ctor, "csharpsquid:S4212").is_empty());

        // Boundary: unrelated two-parameter constructors stay untouched.
        let plain_ctor =
            analyze_default("class Item\n{\n    public Item(int a, string b) { }\n}\n");
        assert!(with_key(&plain_ctor, "csharpsquid:S4212").is_empty());
    }

    #[test]
    fn s3926_requires_deserialization_hook_for_optional_fields() {
        let unhooked = analyze_default(
            "[Serializable]\nclass Doc\n{\n    [OptionalField]\n    private int version;\n}\n",
        );
        let flagged = with_key(&unhooked, "csharpsquid:S3926");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 4);

        let hooked = analyze_default(
            "[Serializable]\nclass Doc\n{\n    [OptionalField]\n    private int version;\n\n    [OnDeserialized]\n    private void OnFixup(StreamingContext ctx) { }\n}\n",
        );
        assert!(with_key(&hooked, "csharpsquid:S3926").is_empty());
    }

    #[test]
    fn s3927_checks_serialization_callback_shapes() {
        let wrong_shape = analyze_default(
            "class Doc\n{\n    [OnSerializing]\n    void Before(SerializationInfo info) { }\n}\n",
        );
        let flagged = with_key(&wrong_shape, "csharpsquid:S3927");
        assert_eq!(flagged.len(), 1);

        // Boundary: the canonical '(StreamingContext)' shape passes.
        let right_shape = analyze_default(
            "class Doc\n{\n    [OnSerializing]\n    void Before(StreamingContext ctx) { }\n}\n",
        );
        assert!(with_key(&right_shape, "csharpsquid:S3927").is_empty());
    }

    #[test]
    fn s3928_matches_param_name_with_enclosing_parameters() {
        let mismatched = analyze_default(
            "class Guard\n{\n    void Check(int amount)\n    {\n        throw new ArgumentException(\"bad\", \"value\");\n    }\n}\n",
        );
        let flagged = with_key(&mismatched, "csharpsquid:S3928");
        assert_eq!(flagged.len(), 1);

        // Boundary: naming the real parameter stays clean; non-literal
        // arguments are unverifiable and skipped.
        let matched = analyze_default(
            "class Guard\n{\n    void Check(int amount)\n    {\n        throw new ArgumentException(\"bad\", nameof(amount));\n    }\n}\n",
        );
        assert!(with_key(&matched, "csharpsquid:S3928").is_empty());

        let named = analyze_default(
            "class Guard\n{\n    void Check(int amount)\n    {\n        throw new ArgumentException(\"bad\", \"amount\");\n    }\n}\n",
        );
        assert!(with_key(&named, "csharpsquid:S3928").is_empty());
    }

    #[test]
    fn s4581_flags_parameterless_guid_creation() {
        let empty = analyze_default("class C\n{\n    Guid g = new Guid();\n}\n");
        let flagged = with_key(&empty, "csharpsquid:S4581");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.column, 13);

        // Boundary: byte-argument creation and NewGuid stay clean.
        let from_bytes = analyze_default("class C\n{\n    Guid g = new Guid(bytes);\n}\n");
        assert!(with_key(&from_bytes, "csharpsquid:S4581").is_empty());

        let fresh = analyze_default("class C\n{\n    Guid g = Guid.NewGuid();\n}\n");
        assert!(with_key(&fresh, "csharpsquid:S4581").is_empty());
    }

    #[test]
    fn s4260_matches_constructor_argument_names_with_constructors() {
        let unknown_name = analyze_default(
            "class Shape\n{\n    [ConstructorArgument(\"radius\")]\n    public double Width { get; set; }\n}\n",
        );
        let flagged = with_key(&unknown_name, "csharpsquid:S4260");
        assert_eq!(flagged.len(), 1);

        let known_name = analyze_default(
            "class Shape\n{\n    public Shape(double radius) { }\n\n    [ConstructorArgument(\"radius\")]\n    public double Width { get; set; }\n}\n",
        );
        assert!(with_key(&known_name, "csharpsquid:S4260").is_empty());
    }

    #[test]
    fn s4428_requires_export_besides_part_creation_policy() {
        let unexported =
            analyze_default("[PartCreationPolicy(CreationPolicy.NonShared)]\nclass Engine\n{\n}\n");
        let flagged = with_key(&unexported, "csharpsquid:S4428");
        assert_eq!(flagged.len(), 1);

        let exported = analyze_default(
            "[Export]\n[PartCreationPolicy(CreationPolicy.NonShared)]\nclass Engine\n{\n}\n",
        );
        assert!(with_key(&exported, "csharpsquid:S4428").is_empty());
    }

    #[test]
    fn s4423_flags_deprecated_tls_protocols() {
        let deprecated = analyze_default(
            "class Net\n{\n    void Lock()\n    {\n        ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3;\n    }\n}\n",
        );
        let flagged = with_key(&deprecated, "csharpsquid:S4423");
        assert_eq!(flagged.len(), 1);

        // Boundary: modern protocol members stay clean.
        let modern = analyze_default(
            "class Net\n{\n    void Open()\n    {\n        var protocols = SslProtocols.Tls13 | SslProtocols.Tls12;\n    }\n}\n",
        );
        assert!(with_key(&modern, "csharpsquid:S4423").is_empty());
    }

    #[test]
    fn s4790_flags_md5_and_sha1_usage() {
        let weak = analyze_default(
            "using System.Security.Cryptography;\nclass Hash\n{\n    byte[] Bad(byte[] data)\n    {\n        return MD5.Create().ComputeHash(data);\n    }\n}\n",
        );
        let flagged = with_key(&weak, "csharpsquid:S4790");
        assert_eq!(flagged.len(), 1);

        // Boundary: the using import alone is not a usage.
        let imported_only =
            analyze_default("using System.Security.Cryptography;\nclass Hash\n{\n}\n");
        assert!(with_key(&imported_only, "csharpsquid:S4790").is_empty());
    }

    #[test]
    fn s5542_flags_insecure_cipher_modes_and_padding() {
        let insecure = analyze_default(
            "class Crypto\n{\n    Aes Make()\n    {\n        var aes = Aes.Create();\n        aes.Mode = CipherMode.ECB;\n        aes.Padding = PaddingMode.None;\n        return aes;\n    }\n}\n",
        );
        let flagged = with_key(&insecure, "csharpsquid:S5542");
        assert_eq!(flagged.len(), 2);

        let secure = analyze_default(
            "class Crypto\n{\n    Aes Make()\n    {\n        var aes = Aes.Create();\n        aes.Mode = CipherMode.CBC;\n        aes.Padding = PaddingMode.PKCS7;\n        return aes;\n    }\n}\n",
        );
        assert!(with_key(&secure, "csharpsquid:S5542").is_empty());
    }

    #[test]
    fn s5547_flags_legacy_block_ciphers() {
        let legacy = analyze_default(
            "class Vault\n{\n    DES des = DESCryptoServiceProvider.Create();\n}\n",
        );
        let flagged = with_key(&legacy, "csharpsquid:S5547");
        assert_eq!(flagged.len(), 2);

        let robust = analyze_default("class Vault\n{\n    Aes aes = Aes.Create();\n}\n");
        assert!(with_key(&robust, "csharpsquid:S5547").is_empty());
    }

    #[test]
    fn s4426_flags_weak_asymmetric_providers_and_short_keys() {
        let legacy_provider = analyze_default(
            "class Sign\n{\n    RSA Make() => new RSACryptoServiceProvider(1024);\n}\n",
        );
        assert!(!with_key(&legacy_provider, "csharpsquid:S4426").is_empty());

        let short_key = analyze_default(
            "class Sign\n{\n    void Configure(RSA rsa)\n    {\n        rsa.KeySize = 1024;\n    }\n}\n",
        );
        let flagged = with_key(&short_key, "csharpsquid:S4426");
        assert_eq!(flagged.len(), 1);

        // Boundary: 2048 bits meets the floor.
        let adequate_key = analyze_default(
            "class Sign\n{\n    void Configure(RSA rsa)\n    {\n        rsa.KeySize = 2048;\n    }\n}\n",
        );
        assert!(with_key(&adequate_key, "csharpsquid:S4426").is_empty());
    }

    #[test]
    fn s5659_flags_weak_jwt_algorithms_in_token_contexts() {
        let weak = analyze_default(
            "class Auth\n{\n    TokenValidationParameters Make()\n    {\n        return new TokenValidationParameters { ValidAlgorithms = new[] { \"HS256\" } };\n    }\n}\n",
        );
        let flagged = with_key(&weak, "csharpsquid:S5659");
        assert_eq!(flagged.len(), 1);

        // Boundary: strong algorithms stay clean even in token contexts, and
        // weak spellings outside JWT contexts are untouched.
        let strong = analyze_default(
            "class Auth\n{\n    TokenValidationParameters Make()\n    {\n        return new TokenValidationParameters { ValidAlgorithms = new[] { \"RS256\" } };\n    }\n}\n",
        );
        assert!(with_key(&strong, "csharpsquid:S5659").is_empty());

        let outside_jwt = analyze_default("class Codec\n{\n    string Mode() => \"HS256\";\n}\n");
        assert!(with_key(&outside_jwt, "csharpsquid:S5659").is_empty());
    }

    #[test]
    fn s5332_flags_clear_text_url_literals() {
        let clear_text = analyze_default(
            "class Feed\n{\n    string Endpoint() => \"http://api.example.com/v1\";\n}\n",
        );
        let flagged = with_key(&clear_text, "csharpsquid:S5332");
        assert_eq!(flagged.len(), 1);

        // Boundary: encrypted channels, loopback targets, and XML namespaces
        // stay clean.
        let secure = analyze_default(
            "class Feed\n{\n    string Endpoint() => \"https://api.example.com/v1\";\n}\n",
        );
        assert!(with_key(&secure, "csharpsquid:S5332").is_empty());

        let namespace_uri = analyze_default(
            "class Doc\n{\n    string Xmlns() => \"http://www.w3.org/2001/XMLSchema\";\n}\n",
        );
        assert!(with_key(&namespace_uri, "csharpsquid:S5332").is_empty());
    }

    #[test]
    fn s5443_flags_publicly_writable_temp_paths() {
        let public_dir =
            analyze_default("class Scratch\n{\n    string Spot() => \"/tmp/build-cache\";\n}\n");
        let flagged = with_key(&public_dir, "csharpsquid:S5443");
        assert_eq!(flagged.len(), 1);

        // Boundary: app-private locations stay clean.
        let private_dir = analyze_default(
            "class Scratch\n{\n    string Spot() => Path.Combine(appData, \"cache\")\n;\n}\n",
        );
        assert!(with_key(&private_dir, "csharpsquid:S5443").is_empty());
    }

    #[test]
    fn s5445_flags_predictable_temp_file_apis() {
        let predictable = analyze_default(
            "class Upload\n{\n    void Stash()\n    {\n        var path = Path.GetTempFileName();\n    }\n}\n",
        );
        let flagged = with_key(&predictable, "csharpsquid:S5445");
        assert_eq!(flagged.len(), 1);

        // Boundary: other 'Path' helpers stay untouched.
        let directory_helper =
            analyze_default("class Upload\n{\n    string Dir() => Path.GetTempPath();\n}\n");
        assert!(with_key(&directory_helper, "csharpsquid:S5445").is_empty());
    }

    #[test]
    fn s4507_flags_debugging_enabled_in_config_literals() {
        let debug_on = analyze_default(
            "class Boot\n{\n    string Config() => \"<customErrors mode=\\\"Off\\\"/>\";\n}\n",
        );
        assert_eq!(with_key(&debug_on, "csharpsquid:S4507").len(), 1);

        let compile_debug = analyze_default(
            "class Boot\n{\n    string Config() => \"<compilation debug=\\\"true\\\">\";\n}\n",
        );
        assert_eq!(with_key(&compile_debug, "csharpsquid:S4507").len(), 1);

        // Boundary: production-safe spellings stay clean.
        let remote_only = analyze_default(
            "class Boot\n{\n    string Config() => \"<customErrors mode=\\\"RemoteOnly\\\"/>\";\n}\n",
        );
        assert!(with_key(&remote_only, "csharpsquid:S4507").is_empty());
    }

    #[test]
    fn s5753_flags_request_validation_disabled() {
        let directive = analyze_default(
            "class Pages\n{\n    string Template() => \"<@ Page validateRequest=\\\"false\\\" %>\";\n}\n",
        );
        assert_eq!(with_key(&directive, "csharpsquid:S5753").len(), 1);

        let validate_input = analyze_default(
            "class Legacy\n{\n    void Post()\n    {\n        ValidateInput(false);\n    }\n}\n",
        );
        let flagged = with_key(&validate_input, "csharpsquid:S5753");
        assert_eq!(flagged.len(), 1);

        // Boundary: leaving validation on is clean.
        let enabled = analyze_default(
            "class Legacy\n{\n    void Post()\n    {\n        ValidateInput(true);\n    }\n}\n",
        );
        assert!(with_key(&enabled, "csharpsquid:S5753").is_empty());
    }

    #[test]
    fn s4502_flags_antiforgery_disabled_assignments() {
        let disabled = analyze_default(
            "class Setup\n{\n    void Configure(AntiforgeryOptions options)\n    {\n        options.Antiforgery.Enabled = false;\n    }\n}\n",
        );
        assert_eq!(with_key(&disabled, "csharpsquid:S4502").len(), 1);

        // Boundary: unrelated or enabling assignments stay clean.
        let untouched = analyze_default(
            "class Setup\n{\n    void Configure(AntiforgeryOptions options)\n    {\n        options.Enabled = true;\n    }\n}\n",
        );
        assert!(with_key(&untouched, "csharpsquid:S4502").is_empty());
    }

    #[test]
    fn s5773_flags_typename_handling_beyond_none() {
        let permissive = analyze_default(
            "class Wire\n{\n    JsonSerializerSettings Make() => new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };\n}\n",
        );
        let flagged = with_key(&permissive, "csharpsquid:S5773");
        assert_eq!(flagged.len(), 1);

        // Boundary: 'TypeNameHandling.None' (or no mention) stays clean.
        let safe = analyze_default(
            "class Wire\n{\n    JsonSerializerSettings Make() => new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None };\n}\n",
        );
        assert!(with_key(&safe, "csharpsquid:S5773").is_empty());
    }

    #[test]
    fn s5042_flags_unbounded_archive_extraction() {
        let unbounded = analyze_default(
            "class Unpack\n{\n    void Extract(ZipArchive archive, string target)\n    {\n        archive.ExtractToDirectory(target);\n        ZipFile.ExtractToDirectory(archivePath, target);\n    }\n}\n",
        );
        let flagged = with_key(&unbounded, "csharpsquid:S5042");
        assert_eq!(flagged.len(), 2);

        // Boundary: unrelated methods stay untouched.
        let unrelated = analyze_default("class Store\n{\n    void Put(string key) { }\n}\n");
        assert!(with_key(&unrelated, "csharpsquid:S5042").is_empty());
    }

    #[test]
    fn s5122_flags_any_origin_cors_policies() {
        let any_origin = analyze_default(
            "class Api\n{\n    void Configure(CorsPolicyBuilder policy)\n    {\n        policy.AllowAnyOrigin();\n    }\n}\n",
        );
        assert_eq!(with_key(&any_origin, "csharpsquid:S5122").len(), 1);

        let wildcard_header = analyze_default(
            "class Api\n{\n    string Header() => \"Access-Control-Allow-Origin: *\";\n}\n",
        );
        assert_eq!(with_key(&wildcard_header, "csharpsquid:S5122").len(), 1);

        // Boundary: pinned origins stay clean.
        let pinned = analyze_default(
            "class Api\n{\n    void Configure(CorsPolicyBuilder policy)\n    {\n        policy.WithOrigins(\"https://app.example.com\");\n    }\n}\n",
        );
        assert!(with_key(&pinned, "csharpsquid:S5122").is_empty());
    }

    #[test]
    fn s7039_flags_unsafe_csp_sources() {
        let unsafe_inline = analyze_default(
            "class Headers\n{\n    string Policy() => \"Content-Security-Policy: default-src 'self'; script-src 'unsafe-inline'\";\n}\n",
        );
        assert_eq!(with_key(&unsafe_inline, "csharpsquid:S7039").len(), 1);

        // Boundary: a strict policy without unsafe sources stays clean.
        let strict = analyze_default(
            "class Headers\n{\n    string Policy() => \"Content-Security-Policy: default-src 'self'\";\n}\n",
        );
        assert!(with_key(&strict, "csharpsquid:S7039").is_empty());
    }

    #[test]
    fn s5693_flags_oversized_request_body_limits() {
        let oversized = analyze_default(
            "class Limits\n{\n    void Configure(FormOptions options)\n    {\n        options.MultipartBodyLengthLimit = 16777216;\n    }\n}\n",
        );
        let flagged = with_key(&oversized, "csharpsquid:S5693");
        assert_eq!(flagged.len(), 1);

        // Boundary: the tolerated maximum itself passes.
        let at_limit = analyze_default(
            "class Limits\n{\n    void Configure(FormOptions options)\n    {\n        options.MultipartBodyLengthLimit = 8388608;\n    }\n}\n",
        );
        assert!(with_key(&at_limit, "csharpsquid:S5693").is_empty());
    }

    #[test]
    fn s6354_flags_direct_system_clock_reads() {
        let direct = analyze_default(
            "class Report\n{\n    string Stamp() => DateTime.UtcNow.ToString();\n}\n",
        );
        let flagged = with_key(&direct, "csharpsquid:S6354");
        assert_eq!(flagged.len(), 1);

        // Boundary: a passed-in value carries no clock read.
        let injected = analyze_default(
            "class Report\n{\n    string Stamp(DateTime when) => when.ToString();\n}\n",
        );
        assert!(with_key(&injected, "csharpsquid:S6354").is_empty());
    }

    #[test]
    fn s6561_flags_datetime_now_near_stopwatch() {
        let timing = analyze_default(
            "class Bench\n{\n    void Measure()\n    {\n        var watch = Stopwatch.StartNew();\n        var started = DateTime.Now;\n        watch.Stop();\n    }\n}\n",
        );
        let flagged = with_key(&timing, "csharpsquid:S6561");
        assert_eq!(flagged.len(), 1);

        // Boundary: 'DateTime.Now' outside a timing method is S6354's
        // territory, not this rule's.
        let untimed =
            analyze_default("class Report\n{\n    string Stamp() => DateTime.Now.ToString();\n}\n");
        assert!(with_key(&untimed, "csharpsquid:S6561").is_empty());
    }

    #[test]
    fn s6562_requires_datetime_kind_on_construction() {
        let unspecified = analyze_default(
            "class Clock\n{\n    DateTime Make() => new DateTime(2020, 5, 1);\n}\n",
        );
        let flagged = with_key(&unspecified, "csharpsquid:S6562");
        assert_eq!(flagged.len(), 1);

        // Boundary: an explicit kind settles the meaning.
        let specified = analyze_default(
            "class Clock\n{\n    DateTime Make() => new DateTime(2020, 5, 1, 0, 0, 0, DateTimeKind.Utc);\n}\n",
        );
        assert!(with_key(&specified, "csharpsquid:S6562").is_empty());
    }

    #[test]
    fn s6588_flags_unix_epoch_literals() {
        let epoch = analyze_default(
            "class Sync\n{\n    DateTime Epoch() => new DateTime(1970, 1, 1);\n}\n",
        );
        let flagged = with_key(&epoch, "csharpsquid:S6588");
        assert_eq!(flagged.len(), 1);

        // Boundary: any other date stays untouched.
        let other = analyze_default(
            "class Sync\n{\n    DateTime Start() => new DateTime(1971, 1, 1);\n}\n",
        );
        assert!(with_key(&other, "csharpsquid:S6588").is_empty());
    }

    #[test]
    fn s6575_flags_windows_time_zone_lookups_without_converter() {
        let windows_only = analyze_default(
            "class Zones\n{\n    TimeZoneInfo Resolve(string id) => TimeZoneInfo.FindSystemTimeZoneById(id);\n}\n",
        );
        let flagged = with_key(&windows_only, "csharpsquid:S6575");
        assert_eq!(flagged.len(), 1);

        // Boundary: once 'TimeZoneConverter' is referenced the migration is
        // considered underway and the file stays clean.
        let converter_present = analyze_default(
            "using TimeZoneConverter;\nclass Zones\n{\n    TimeZoneInfo Resolve(string id) => TZConvert.GetTimeZoneInfo(id);\n}\n",
        );
        assert!(with_key(&converter_present, "csharpsquid:S6575").is_empty());
    }

    #[test]
    fn s6580_flags_culture_less_date_parsing() {
        let culture_less = analyze_default(
            "class Feed\n{\n    DateTime Read(string raw) => DateTime.Parse(raw);\n}\n",
        );
        let flagged = with_key(&culture_less, "csharpsquid:S6580");
        assert_eq!(flagged.len(), 1);

        // Boundary: passing a culture satisfies the rule.
        let cultured = analyze_default(
            "class Feed\n{\n    DateTime Read(string raw) => DateTime.Parse(raw, CultureInfo.InvariantCulture);\n}\n",
        );
        assert!(with_key(&cultured, "csharpsquid:S6580").is_empty());
    }

    #[test]
    fn s6585_flags_hardcoded_date_format_strings() {
        let fixed_format = analyze_default(
            "class Report\n{\n    string Stamp(DateTime when) => when.ToString(\"yyyy-MM-dd HH:mm:ss\");\n}\n",
        );
        let flagged = with_key(&fixed_format, "csharpsquid:S6585");
        assert_eq!(flagged.len(), 1);

        // Boundary: non-date format spellings stay clean.
        let currency_format = analyze_default(
            "class Report\n{\n    string Price(decimal amount) => amount.ToString(\"C\");\n}\n",
        );
        assert!(with_key(&currency_format, "csharpsquid:S6585").is_empty());
    }

    #[test]
    fn s6419_flags_mutable_state_in_azure_function_classes() {
        let mutable = analyze_default(
            "class Greeter\n{\n    private int hits;\n\n    [FunctionName(\"Ping\")]\n    public void Ping() { }\n}\n",
        );
        let flagged = with_key(&mutable, "csharpsquid:S6419");
        assert_eq!(flagged.len(), 1);

        // Boundary: immutable members do not leak state between invocations.
        let immutable = analyze_default(
            "class Greeter\n{\n    private readonly int total = 0;\n\n    [FunctionName(\"Ping\")]\n    public void Ping() { }\n}\n",
        );
        assert!(with_key(&immutable, "csharpsquid:S6419").is_empty());
    }

    #[test]
    fn s6421_requires_try_catch_in_azure_functions() {
        let unprotected = analyze_default(
            "class Greeter\n{\n    [FunctionName(\"Ping\")]\n    public void Ping()\n    {\n        Send();\n    }\n}\n",
        );
        let flagged = with_key(&unprotected, "csharpsquid:S6421");
        assert_eq!(flagged.len(), 1);

        // Boundary: a guarded body satisfies the rule.
        let guarded = analyze_default(
            "class Greeter\n{\n    [FunctionName(\"Ping\")]\n    public void Ping()\n    {\n        try { Send(); } catch (System.Exception ex) { logger.LogError(ex, \"failed\"); }\n    }\n}\n",
        );
        assert!(with_key(&guarded, "csharpsquid:S6421").is_empty());
    }

    #[test]
    fn s6422_flags_blocking_inside_azure_function_classes() {
        let blocking = analyze_default(
            "class OrderFn\n{\n    [FunctionName(\"Run\")]\n    public int Run()\n    {\n        var task = System.Threading.Tasks.Task.Run(() => 1);\n        return task.Result;\n    }\n}\n",
        );
        assert!(!with_key(&blocking, "csharpsquid:S6422").is_empty());

        // Boundary: the same access outside a Function class is not this
        // rule's concern.
        let outside = analyze_default(
            "class Worker\n{\n    public int Block()\n    {\n        var task = System.Threading.Tasks.Task.Run(() => 1);\n        return task.Result;\n    }\n}\n",
        );
        assert!(with_key(&outside, "csharpsquid:S6422").is_empty());
    }

    #[test]
    fn s6423_requires_logging_inside_azure_function_catches() {
        let silent = analyze_default(
            "class OrderFn\n{\n    [FunctionName(\"Run\")]\n    public void Run()\n    {\n        try { Send(); } catch (System.Exception ex) { throw; }\n    }\n}\n",
        );
        let flagged = with_key(&silent, "csharpsquid:S6423");
        assert_eq!(flagged.len(), 1);

        // Boundary: a catch that reports the failure stays clean.
        let reporting = analyze_default(
            "class OrderFn\n{\n    [FunctionName(\"Run\")]\n    public void Run()\n    {\n        try { Send(); } catch (System.Exception ex) { _log.Error(ex, \"run failed\"); }\n    }\n}\n",
        );
        assert!(with_key(&reporting, "csharpsquid:S6423").is_empty());
    }

    #[test]
    fn s6420_flags_clients_built_per_invocation() {
        let per_call = analyze_default(
            "class OrderFn\n{\n    [FunctionName(\"Run\")]\n    public void Run()\n    {\n        var client = new BlobContainerClient(\"conn\", \"orders\");\n    }\n}\n",
        );
        let flagged = with_key(&per_call, "csharpsquid:S6420");
        assert_eq!(flagged.len(), 1);

        // Boundary: the same creation outside a Function is untouched here.
        let elsewhere = analyze_default(
            "class Hosted\n{\n    public void Start()\n    {\n        var client = new BlobContainerClient(\"conn\", \"orders\");\n    }\n}\n",
        );
        assert!(with_key(&elsewhere, "csharpsquid:S6420").is_empty());
    }

    #[test]
    fn s6798_requires_public_on_js_invokable_methods() {
        let mixed = analyze_default(
            "class Counter\n{\n    [JSInvokable]\n    public void Increment() { }\n\n    [JSInvokable]\n    internal void Reset() { }\n}\n",
        );
        let flagged = with_key(&mixed, "csharpsquid:S6798");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);
    }

    #[test]
    fn s6930_flags_backslashes_in_route_templates() {
        let windows_route = analyze_default(
            "class UsersController : ControllerBase\n{\n    [HttpGet(\"users\\\\list\")]\n    public IActionResult List() => Ok();\n}\n",
        );
        let flagged = with_key(&windows_route, "csharpsquid:S6930");
        assert_eq!(flagged.len(), 1);

        // Boundary: forward slashes are portable.
        let portable_route = analyze_default(
            "class UsersController : ControllerBase\n{\n    [HttpGet(\"users/list\")]\n    public IActionResult List() => Ok();\n}\n",
        );
        assert!(with_key(&portable_route, "csharpsquid:S6930").is_empty());
    }

    #[test]
    fn s6931_flags_rooted_action_route_templates() {
        let rooted = analyze_default(
            "class UsersController : ControllerBase\n{\n    [HttpGet(\"/users\")]\n    public IActionResult List() => Ok();\n}\n",
        );
        let flagged = with_key(&rooted, "csharpsquid:S6931");
        assert_eq!(flagged.len(), 1);

        // Boundary: tilde-rooted and controller-level templates stay clean.
        let tilde_rooted = analyze_default(
            "class UsersController : ControllerBase\n{\n    [HttpGet(\"~/users\")]\n    public IActionResult List() => Ok();\n}\n",
        );
        assert!(with_key(&tilde_rooted, "csharpsquid:S6931").is_empty());

        let controller_level = analyze_default(
            "[Route(\"api/users\")]\nclass UsersController : ControllerBase\n{\n}\n",
        );
        assert!(with_key(&controller_level, "csharpsquid:S6931").is_empty());
    }

    #[test]
    fn s6934_requires_controller_level_route_for_action_templates() {
        let missing = analyze_default(
            "class UsersController\n{\n    [Route(\"list\")]\n    public IActionResult List() => Ok();\n}\n",
        );
        let flagged = with_key(&missing, "csharpsquid:S6934");
        assert_eq!(flagged.len(), 1);

        // Boundary: a controller-level route covers the actions.
        let present = analyze_default(
            "[Route(\"api/users\")]\nclass UsersController\n{\n    [HttpGet(\"list\")]\n    public IActionResult List() => Ok();\n}\n",
        );
        assert!(with_key(&present, "csharpsquid:S6934").is_empty());
    }

    #[test]
    fn s6932_flags_raw_request_reads() {
        let raw_read = analyze_default(
            "class LegacyApi\n{\n    void Read()\n    {\n        var form = Request.Form;\n    }\n}\n",
        );
        let flagged = with_key(&raw_read, "csharpsquid:S6932");
        assert_eq!(flagged.len(), 1);

        // Boundary: other request members stay untouched.
        let headers_only = analyze_default(
            "class LegacyApi\n{\n    void Read()\n    {\n        var agent = Request.Headers[\"User-Agent\"];\n    }\n}\n",
        );
        assert!(with_key(&headers_only, "csharpsquid:S6932").is_empty());
    }

    #[test]
    fn s6961_prefers_controller_base_for_api_controllers() {
        let view_base =
            analyze_default("[ApiController]\nclass ProductsController : Controller\n{\n}\n");
        let flagged = with_key(&view_base, "csharpsquid:S6961");
        assert_eq!(flagged.len(), 1);

        // Boundary: 'ControllerBase' and MVC view controllers without API
        // markers both stay clean.
        let base_ok =
            analyze_default("[ApiController]\nclass ProductsController : ControllerBase\n{\n}\n");
        assert!(with_key(&base_ok, "csharpsquid:S6961").is_empty());

        let mvc_views = analyze_default(
            "class HomeController : Controller\n{\n    public IActionResult Index() => View();\n}\n",
        );
        assert!(with_key(&mvc_views, "csharpsquid:S6961").is_empty());
    }

    #[test]
    fn s6962_flags_hand_rolled_http_clients() {
        let manual =
            analyze_default("class Fetcher\n{\n    HttpClient Make() => new HttpClient();\n}\n");
        let flagged = with_key(&manual, "csharpsquid:S6962");
        assert_eq!(flagged.len(), 1);

        // Boundary: similarly named handlers are not clients.
        let handler =
            analyze_default("class Fetcher\n{\n    var handler = new HttpClientHandler();\n}\n");
        assert!(with_key(&handler, "csharpsquid:S6962").is_empty());
    }

    #[test]
    fn s6965_requires_verb_attributes_on_actions() {
        let unannotated = analyze_default(
            "class WidgetsController\n{\n    public IActionResult Get() => Ok();\n\n    [HttpGet]\n    public IActionResult List() => Ok();\n\n    public void Utility() { }\n}\n",
        );
        let flagged = with_key(&unannotated, "csharpsquid:S6965");
        assert_eq!(flagged.len(), 2);
    }

    #[test]
    fn s6967_requires_model_state_check_for_bound_models() {
        let unchecked = analyze_default(
            "class OrdersController\n{\n    public IActionResult Create(OrderDto dto) => Ok();\n}\n",
        );
        let flagged = with_key(&unchecked, "csharpsquid:S6967");
        assert_eq!(flagged.len(), 1);

        // Boundary: validated bodies and primitive parameters stay clean.
        let checked = analyze_default(
            "class OrdersController\n{\n    public IActionResult Create(OrderDto dto)\n    {\n        if (!ModelState.IsValid) return BadRequest();\n        return Ok();\n    }\n}\n",
        );
        assert!(with_key(&checked, "csharpsquid:S6967").is_empty());

        let primitive = analyze_default(
            "class OrdersController\n{\n    public IActionResult Get(int id) => Ok();\n}\n",
        );
        assert!(with_key(&primitive, "csharpsquid:S6967").is_empty());
    }

    #[test]
    fn s6968_requires_produces_response_type_on_actions() {
        let undeclared = analyze_default(
            "class OrdersController\n{\n    [HttpPost]\n    public IActionResult Create(OrderDto dto) => Ok();\n}\n",
        );
        let flagged = with_key(&undeclared, "csharpsquid:S6968");
        assert_eq!(flagged.len(), 1);

        // Boundary: declared responses and void commands stay clean.
        let declared = analyze_default(
            "class OrdersController\n{\n    [HttpPost]\n    [ProducesResponseType(typeof(OrderDto), 200)]\n    public IActionResult Create(OrderDto dto) => Ok();\n}\n",
        );
        assert!(with_key(&declared, "csharpsquid:S6968").is_empty());

        let void_action = analyze_default(
            "class OrdersController\n{\n    [HttpPost]\n    public void Queue(OrderDto dto) { }\n}\n",
        );
        assert!(with_key(&void_action, "csharpsquid:S6968").is_empty());
    }
    #[test]
    fn s6670_flags_trace_writes() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        Trace.WriteLine(\"m\");\n            System.Diagnostics.Trace.Write(\"x\");\n        logger.Log(\"fine\");\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S6670");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);

        let clean = analyze_default(
            "class A\n{\n    void M()\n    {\n        logger.Log(\"fine\");\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S6670").is_empty());
    }

    #[test]
    fn s6675_flags_trace_switch_gates() {
        let report = analyze_default(
            "class A\n{\n    void M(bool enabled)\n    {\n        Trace.WriteLineIf(traceSwitch.TraceInfo, \"m\");\n        Trace.WriteLineIf(enabled, \"m\");\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S6675");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s6664_limits_log_calls_per_method() {
        let chatty = "class A\n{\n    void M()\n    {\n        logger.LogDebug(\"a\");\n            logger.LogDebug(\"b\");\n        logger.LogDebug(\"c\");\n        logger.LogDebug(\"d\");\n        logger.LogDebug(\"e\");\n    }\n}\n";
        let report = analyze_default(chatty);
        let flagged = with_key(&report, "csharpsquid:S6664");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);

        let at_limit = analyze_default(
            "class A\n{\n    void M()\n    {\n        logger.LogDebug(\"a\");\n            logger.LogDebug(\"b\");\n        logger.LogDebug(\"c\");\n        logger.LogDebug(\"d\");\n    }\n}\n",
        );
        assert!(with_key(&at_limit, "csharpsquid:S6664").is_empty());

        let warnings = analyze_default(
            "class A\n{\n    void M()\n    {\n        logger.LogWarning(\"one\");\n            logger.LogWarning(\"two\");\n    }\n}\n",
        );
        assert_eq!(with_key(&warnings, "csharpsquid:S6664").len(), 1);
    }

    #[test]
    fn s6673_flags_swapped_placeholders() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        logger.LogWarning(\"{Y} and {X}\", x, y);\n            logger.LogInformation(\"{X} and {Y}\", x, y);\n        logger.LogError(\"{n} of {m}\", a, b);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S6673");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s6674_flags_malformed_templates() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        logger.LogDebug(\"Broken {Count\");\n            logger.LogInformation(\"oops } done\");\n        logger.LogWarning(\"Fine {Total}\", total);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S6674");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s6677_flags_duplicate_placeholders() {
        let report = analyze_default(
            "class A\n{\n    void M(int id)\n    {\n        logger.LogInformation(\"{Id} then {Id}\", id, id);\n        logger.LogDebug(\"{Name} not {Name2}\", name, name2);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S6677");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s6678_flags_placeholder_casing() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        logger.LogDebug(\"User {userName} did {Action}\", user, action);\n            logger.LogError(\"Code {0} fired\", code);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S6678");
        assert_eq!(flagged.len(), 1);
        assert_eq!(
            flagged[0].message,
            "Rename the placeholder {userName} to PascalCase."
        );
    }

    #[test]
    fn s6667_requires_exception_in_catch_logging() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        try { Run(); } catch (System.Exception ex) { logger.LogError(\"Failed\"); }\n            try { Run(); } catch (System.Exception ex) { logger.LogError(\"Failed {Cause}\", ex); }\n        try { Run(); } catch (System.Exception) { logger.LogError(\"Failed again\"); }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S6667");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s2629_requires_constant_templates() {
        let report = analyze_default(
            "class A\n{\n    void M(string template)\n    {\n        logger.LogDebug(template);\n            logger.LogInformation($\"Value {Value}\");\n        logger.LogWarning(\"Plain {Name}\", name);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2629");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s1312_shapes_logger_fields() {
        let flagged_report = analyze_default("class A\n{\n    Logger _logger;\n}\n");
        assert_eq!(with_key(&flagged_report, "csharpsquid:S1312").len(), 1);

        let clean = analyze_default("class A\n{\n    private static readonly Logger _logger;\n}\n");
        assert!(with_key(&clean, "csharpsquid:S1312").is_empty());

        let untyped = analyze_default("class A\n{\n    private int count;\n}\n");
        assert!(with_key(&untyped, "csharpsquid:S1312").is_empty());
    }

    #[test]
    fn s3416_names_create_logger_after_type() {
        let report = analyze_default(
            "class Order\n{\n    void M()\n    {\n        var wrong = factory.CreateLogger<Customer>();\n            var right = factory.CreateLogger<Order>();\n        var typed = factory.CreateLogger(typeof(Order));\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3416");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s6672_matches_ilogger_generic_to_type() {
        let report = analyze_default(
            "class Order\n{\n    private ILogger<Customer> wrong;\n    private ILogger<Order> right;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S6672");
        assert_eq!(flagged.len(), 1);
        assert_eq!(
            flagged[0].message,
            "Use 'ILogger<Order>' for loggers of this type."
        );
    }

    #[test]
    fn s1155_prefers_any_for_emptiness() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        if (items.Count() == 0) return;\n        if (0 == items.Count) return;\n        if (items.Count > 0) return;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1155");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s2275_checks_format_argument_counts() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        text = string.Format(\"{0}-{1}\", one);\n        Console.WriteLine(\"{0}:{1}\", x, y);\n        text = string.Format(CultureInfo.InvariantCulture, \"{0}\", v);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2275");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s3457_validates_composite_formats() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        text = string.Format(\"Malformed {0\", one);\n        text = string.Format(\"No slots here\", one);\n        text = string.Format(\"Ok {0}\", one);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3457");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s3937_flags_irregular_number_patterns() {
        let report = analyze_default(
            "class A\n{\n    void M(int code)\n    {\n        if (code == 1 || code == 2 || code == 5) { }\n        if (code == 1 || code == 3 || code == 5) { }\n        if (code == 7) { }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3937");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s4143_flags_double_element_writes() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        data[0] = 1;\n        data[0] = 2;\n        data[1] = 3;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4143");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
        assert!(flagged[0].message.contains("overwritten"));
    }

    #[test]
    fn s3994_and_s3995_prefer_uri_overloads() {
        let report = analyze_default(
            "class C\n{\n    public string Load(string path) { return path; }\n    public string Load(Uri path) { return \"\"; }\n    public Uri Find(int id) { return null!; }\n    public string Find(string path) { return \"\"; }\n}\n",
        );
        let parameters = with_key(&report, "csharpsquid:S3994");
        assert_eq!(parameters.len(), 1);
        assert_eq!(parameters[0].range.start.line, 3);
        let returns = with_key(&report, "csharpsquid:S3995");
        assert_eq!(returns.len(), 1);
        assert_eq!(returns[0].range.start.line, 6);
    }

    #[test]
    fn s3996_flags_uri_named_string_properties() {
        let report = analyze_default(
            "class C\n{\n    public string HomeUri { get; set; }\n    public string Name { get; set; }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3996");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s4005_passes_uris_to_overloads() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        body = client.DownloadString(\"http://example.com\");\n        body = client.DownloadString(address);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4005");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s3257_suggests_var_for_repeated_types() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        List<int> xs = new List<int>();\n        int age = 5;\n        var zs = new List<int>();\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3257");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s3244_rejects_anonymous_unsubscriptions() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        handler -= () => { };\n        handler -= stored;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3244");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s3247_flags_duplicate_casts() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        var a = (Customer)item;\n        var b = (Customer)item;\n        var c = (Order)item;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3247");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 6);
    }

    #[test]
    fn s1185_rejects_trivial_base_forwarding_overrides() {
        let report = analyze_default(
            "class D : B\n{\n    public override string Name() { return base.Name(); }\n    public override int Size() { var x = base.Size(); return x; }\n    public override void Run() { base.Run(); }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1185");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[1].range.start.line, 5);
    }

    #[test]
    fn s3237_requires_value_in_setters() {
        let report = analyze_default(
            "class E\n{\n    int cached;\n    int Cached\n    {\n        set { cached = value; }\n    }\n    int Other\n    {\n        set { cached = backup; }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3237");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 10);
    }

    #[test]
    fn s4049_converts_accessor_shaped_methods() {
        let report = analyze_default(
            "class F\n{\n    public string GetName() { return name; }\n    public void SetName(string newValue) { this.name = newValue; }\n    public void Reset() { }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4049");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[1].range.start.line, 4);
    }

    #[test]
    fn s4040_flags_lowercase_normalization() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        key = name.ToLower();\n        other = name.ToLowerInvariant();\n        upper = name.ToUpper();\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4040");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s4056_flags_culture_less_conversions() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        text = value.ToString();\n        number = int.Parse(raw);\n        number = double.Parse(raw, culture);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4056");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s4058_requires_comparison_mode() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        same = string.Compare(first, second) == 0;\n        equal = first.Equals(second);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4058");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s1449_requires_culture_for_searches() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        at = text.IndexOf(\"needle\");\n        last = text.LastIndexOf(mark);\n        ordered = text.CompareTo(other);\n        found = text.IndexOf(\"needle\", StringComparison.Ordinal);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1449");
        assert_eq!(flagged.len(), 3);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[2].range.start.line, 7);
    }

    #[test]
    fn s2115_flags_embedded_connection_passwords() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        var leaky = \"Server=s;Database=d;User=u;Password=secret;\";\n        var safe = \"Server=s;Database=d;Integrated Security=true;\";\n        var unset = \"Server=s;Password=;\";\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2115");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s3998_rejects_weak_identity_locks() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        lock (this) { }\n        lock (typeof(A)) { }\n        lock (\"key\") { }\n        lock (gate) { }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3998");
        assert_eq!(flagged.len(), 3);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[2].range.start.line, 7);
    }

    #[test]
    fn s6507_and_s2445_check_lock_guards() {
        let report = analyze_default(
            "class A\n{\n    object gate;\n    readonly object frozen = new object();\n    void M()\n    {\n        lock (gate) { }\n        lock (frozen) { }\n        var local = new object();\n        lock (local) { }\n    }\n}\n",
        );
        let locals = with_key(&report, "csharpsquid:S6507");
        assert_eq!(locals.len(), 1);
        assert_eq!(locals[0].range.start.line, 10);
        let mutable_fields = with_key(&report, "csharpsquid:S2445");
        assert_eq!(mutable_fields.len(), 1);
        assert_eq!(mutable_fields[0].range.start.line, 7);
    }

    #[test]
    fn s3363_flags_datetime_key_members() {
        let report = analyze_default(
            "class R\n{\n    public DateTime CreatedOn { get; set; }\n    public DateTime OrderKey { get; set; }\n    public DateTimeOffset Id { get; set; }\n    private DateTime stamp;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3363");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 4);
        assert_eq!(flagged[1].range.start.line, 5);
    }

    #[test]
    fn s4052_rejects_outdated_base_types() {
        let report = analyze_default(
            "class Bag : ArrayList { }\nclass Map : DictionaryBase { }\nclass Modern : List<int> { }\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4052");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 1);
        assert_eq!(flagged[1].range.start.line, 2);
    }

    #[test]
    fn s2699_requires_test_assertions() {
        let report = analyze_default(
            "class T\n{\n    [Test]\n    public void Verifies() { Assert.That(value, Is.EqualTo(1)); }\n    [Test]\n    public void Sleeps() { Thread.Sleep(10); }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2699");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s2701_flags_literal_assertions() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        Assert.IsTrue(true);\n        widget.IsFalse(false);\n        Assert.IsTrue(ready);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2701");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s2970_completes_assert_that() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        Assert.That(actual);\n        Assert.That(actual, Is.EqualTo(1));\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2970");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s3415_puts_expected_first() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        Assert.AreEqual(result, 5);\n        Assert.AreEqual(5, result);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3415");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s2187_requires_tests_in_classes() {
        let report = analyze_default(
            "[TestClass]\nclass Empty\n{\n    public void Helper() { }\n}\n\n[TestClass]\nclass Real\n{\n    [TestMethod]\n    public void Works() { Assert.IsTrue(true); }\n}\n\nclass Plain { }\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2187");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
    }

    #[test]
    fn s4586_task_methods_do_not_return_null() {
        let report = analyze_default(
            "class A\n{\n    Task Work()\n    {\n        if (ready) { return null; }\n        return Task.CompletedTask;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4586");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);

        let async_safe = analyze_default("class A\n{\n    async Task Go() { return null; }\n}\n");
        assert!(with_key(&async_safe, "csharpsquid:S4586").is_empty());
    }

    #[test]
    fn s3881_and_s2953_check_dispose_contracts() {
        let complete = analyze_default(
            "class Good : IDisposable\n{\n    public void Dispose() { Dispose(true); }\n    protected virtual void Dispose(bool disposing) { }\n    ~Good() { Dispose(false); }\n}\n",
        );
        assert!(with_key(&complete, "csharpsquid:S3881").is_empty());
        assert!(with_key(&complete, "csharpsquid:S2953").is_empty());

        let minimal = analyze_default(
            "class Bad : IDisposable\n{\n    public void Dispose() { done = true; }\n}\n",
        );
        assert_eq!(with_key(&minimal, "csharpsquid:S3881").len(), 2);

        let unattributed = analyze_default("class Sloppy\n{\n    public void Dispose() { }\n}\n");
        let missing = with_key(&unattributed, "csharpsquid:S2953");
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].range.start.line, 1);
    }

    #[test]
    fn s1118_hides_utility_constructors() {
        let report = analyze_default(
            "class Util\n{\n    public static void Run() { }\n    public Util() { }\n}\n\nclass Mixed\n{\n    public void Run() { }\n}\n\nclass Open\n{\n    public static void Run() { }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1118");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 4);
    }

    #[test]
    fn s112_flags_reserved_exception_throws() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        throw new Exception(\"boom\");\n        throw new ApplicationException(\"x\");\n        throw new InvalidOperationException(\"specific\");\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S112");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s1134_and_s1135_track_work_tags() {
        let report = analyze_default(
            "// FIXME: rewrite this loop\nclass A\n{\n    void M()\n    {\n        // TODO: extract helper\n        DoIt(); // TODO inline\n    }\n}\n",
        );
        let fixmes = with_key(&report, "csharpsquid:S1134");
        assert_eq!(fixmes.len(), 1);
        assert_eq!(fixmes[0].range.start.line, 1);
        let todos = with_key(&report, "csharpsquid:S1135");
        assert_eq!(todos.len(), 2);
        assert_eq!(todos[0].range.start.line, 6);
    }

    #[test]
    fn s1163_bans_throws_in_finally() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        try { Work(); } finally { throw new IOException(\"late\"); }\n        throw new IOException(\"early\");\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1163");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s1696_and_s2221_require_specific_catches() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        try { } catch (NullReferenceException broken) { Recover(); }\n        try { } catch (System.Exception general) { Recover(); }\n        try { } catch (IOException io) { Recover(); }\n    }\n}\n",
        );
        let null_catches = with_key(&report, "csharpsquid:S1696");
        assert_eq!(null_catches.len(), 1);
        assert_eq!(null_catches[0].range.start.line, 5);
        let general_catches = with_key(&report, "csharpsquid:S2221");
        assert_eq!(general_catches.len(), 1);
        assert_eq!(general_catches[0].range.start.line, 6);
    }

    #[test]
    fn s2139_single_reports_failures() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        try { Run(); } catch (System.Exception ex) { logger.LogError(\"Boom {Code}\", ex); throw; }\n        try { Run(); } catch (System.Exception ex) { logger.LogError(\"Logged {Code}\", ex); }\n        try { Run(); } catch (System.Exception ex) { throw; }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2139");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s2291_keeps_overflow_checks_on_sum() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        unchecked { total = values.Sum(); }\n        checked { total = values.Sum(); }\n        unchecked { total = values.Count; }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2291");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s2302_prefers_nameof_for_parameter_strings() {
        let report = analyze_default(
            "class A\n{\n    void Save(string userName)\n    {\n        audit = \"userName\";\n        audit = \"user\";\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2302");
        assert_eq!(flagged.len(), 1);
        assert_eq!(
            flagged[0].message,
            "Replace this string with 'nameof(userName)'."
        );
    }

    #[test]
    fn s2327_merges_identical_try_handlers() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        try { One(); } catch (IOException e) { Heal(); } finally { Clean(); }\n        try { Two(); } catch (IOException e) { Heal(); } finally { Clean(); }\n        try { Three(); } catch (ArgumentException e) { Heal(); }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2327");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 6);
    }

    #[test]
    fn s2333_removes_redundant_modifiers() {
        let report = analyze_default(
            "class Holder\n{\n    public string Name { public get; set; }\n}\n\npartial class Solo { }\npartial class Duo { }\npartial class Duo { }\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2333");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s3433_checks_test_method_shapes() {
        let report = analyze_default(
            "class T\n{\n    [Fact]\n    public void Works() { Assert.True(ok); }\n    [Fact]\n    internal void Hidden() { }\n    [Theory]\n    public int Returns() => 1;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3433");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 7);
    }

    #[test]
    fn s2486_and_s2737_require_catch_work() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        try { } catch (System.Exception) { Recover(); }\n        try { } catch (System.Exception) { }\n        try { } catch (System.Exception ex) { throw; }\n        try { } catch (IOException io) { }\n    }\n}\n",
        );
        let ignored = with_key(&report, "csharpsquid:S2486");
        assert_eq!(ignored.len(), 1);
        assert_eq!(ignored[0].range.start.line, 6);
        let rethrow_only = with_key(&report, "csharpsquid:S2737");
        assert_eq!(rethrow_only.len(), 1);
        assert_eq!(rethrow_only[0].range.start.line, 7);
    }

    #[test]
    fn s2757_flags_transposed_operators() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        total =+ amount;\n        sum = a + b;\n        // note: x =+ y in prose\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2757");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s3217_typed_iteration_instead_of_casts() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        foreach (string raw in values)\n            Log(((string)raw).Length);\n        foreach (var other in items)\n            Log(other);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3217");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 6);
    }

    #[test]
    fn s3346_keeps_debug_assert_pure() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        Debug.Assert(Fetch() == 2);\n        Debug.Assert(count == 2);\n        Debug.Assert(total == running++);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3346");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 7);
    }

    #[test]
    fn s3427_disambiguates_optional_overloads() {
        let report = analyze_default(
            "class A\n{\n    public void Fill(int a, int b = 2) { }\n    public void Fill(int a) { }\n    public void Load(int a) { }\n    public void Load(int a, int b, int c = 3) { }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3427");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 4);
    }

    #[test]
    fn s3445_uses_bare_rethrow() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        try { Run(); } catch (IOException ex) { throw ex; }\n        try { Run(); } catch (IOException ex) { throw; }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3445");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s3876_indexes_by_string_or_integer() {
        let report = analyze_default(
            "class Grid\n{\n    public string this[int x, int y] => \"\";\n    public int this[string key] => 0;\n    public double this[double ratio] => 1.0;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3876");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s3878_passes_elements_to_params_calls() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        Use(new[] { 1, 2 });\n        Use(existing);\n        Use(new int[] { 3 });\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3878");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 7);
    }

    #[test]
    fn s3887_consts_readonly_primitive_fields() {
        let report = analyze_default(
            "class A\n{\n    public readonly int limit = 10;\n    private readonly int hidden = 1;\n    public readonly string label = \"x\";\n    public static readonly int cached = 2;\n    public readonly Builder built = new Builder();\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3887");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s3904_requires_assembly_version() {
        let unversioned = analyze_default("[assembly: System.CLSCompliant(false)]\nclass A { }\n");
        let flagged = with_key(&unversioned, "csharpsquid:S3904");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);

        let versioned = analyze_default("[assembly: AssemblyVersion(\"1.0.0.0\")]\nclass A { }\n");
        assert!(with_key(&versioned, "csharpsquid:S3904").is_empty());

        let plain = analyze_default("class A { }\n");
        assert!(with_key(&plain, "csharpsquid:S3904").is_empty());
    }

    #[test]
    fn s3956_hides_list_in_public_signatures() {
        let report = analyze_default(
            "class A\n{\n    public List<int> Get() => xs;\n    public void Add(List<int> xs) { }\n    private List<int> secret;\n    public List<int> exposed;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3956");
        assert_eq!(flagged.len(), 3);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[1].range.start.line, 4);
        assert_eq!(flagged[2].range.start.line, 6);
    }

    #[test]
    fn s4004_makes_collection_properties_readonly() {
        let report = analyze_default(
            "class A\n{\n    public List<int> Items { get; set; }\n    public List<int> Rows { get; }\n    public Dictionary<string, int> Map { get; set; }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4004");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[1].range.start.line, 5);
    }

    #[test]
    fn s4545_references_existing_members_in_debugger_display() {
        let report = analyze_default(
            "[DebuggerDisplay(\"{Name}: {Missing}\")]\nclass Card\n{\n    public string Name { get; set; }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4545");
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].message.contains("'Missing'"));

        let known = analyze_default(
            "[DebuggerDisplay(\"{Name}\")]\nclass Card\n{\n    public string Name { get; set; }\n}\n",
        );
        assert!(with_key(&known, "csharpsquid:S4545").is_empty());
    }
    #[test]
    fn s4487_flags_unreferenced_private_members() {
        let report = analyze_default(
            "class A\n{\n    private int Stale;\n    private void Dead() { }\n    public int Live;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4487");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[1].range.start.line, 4);

        let clean = analyze_default(
            "class B\n{\n    private int used;\n    public int Read() { return used; }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S4487").is_empty());
    }

    #[test]
    fn s4487_skips_attributed_and_partial_members() {
        let attributed = analyze_default(
            "class D\n{\n    [System.Obsolete]\n    private void Legacy() { }\n}\n",
        );
        assert!(with_key(&attributed, "csharpsquid:S4487").is_empty());

        let partial = analyze_default("partial class E\n{\n    private int Maybe;\n}\n");
        assert!(with_key(&partial, "csharpsquid:S4487").is_empty());
    }

    #[test]
    fn s1450_flags_fields_used_by_a_single_method() {
        let report = analyze_default(
            "class A\n{\n    private int counter;\n    public void Bump()\n    {\n        counter = counter + 1;\n        counter++;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1450");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);

        let clean = analyze_default(
            "class B\n{\n    private int value;\n    public void Set(int v) { value = v; }\n    public int Get() { return value; }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S1450").is_empty());
    }

    #[test]
    fn s3459_flags_read_but_never_assigned_fields() {
        let report = analyze_default(
            "class A\n{\n    private int orphan;\n    public int Peek() { return orphan; }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3459");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);

        let clean = analyze_default(
            "class B\n{\n    private int seeded;\n    public B() { seeded = 1; }\n    public void Reset() { seeded = 0; }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S3459").is_empty());
    }

    #[test]
    fn s2933_flags_constructor_only_field_writes() {
        let report = analyze_default(
            "class A\n{\n    private int fixedValue;\n    private int inline = 7;\n    public A() { fixedValue = 42; }\n    public int Total() { return fixedValue + inline; }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2933");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[1].range.start.line, 4);

        let rewritten = analyze_default(
            "class B\n{\n    private int mutableField;\n    public B() { mutableField = 1; }\n    public void Bump() { mutableField++; }\n}\n",
        );
        assert!(with_key(&rewritten, "csharpsquid:S2933").is_empty());

        let mismatched = analyze_default(
            "class C\n{\n    private static int shared;\n    public C() { shared = 1; }\n}\n",
        );
        assert!(with_key(&mismatched, "csharpsquid:S2933").is_empty());
    }

    #[test]
    fn s2325_flags_instance_independent_private_members() {
        let report = analyze_default(
            "class A\n{\n    private int Double(int input) { return input * 2; }\n    public int Call() { return Double(21); }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2325");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);

        let property_report = analyze_default(
            "class C\n{\n    private string Greeting => \"hi\";\n    public string Say() { return Greeting; }\n}\n",
        );
        let properties = with_key(&property_report, "csharpsquid:S2325");
        assert_eq!(properties.len(), 1);
        assert_eq!(properties[0].range.start.line, 3);

        let clean = analyze_default(
            "class B\n{\n    private int state;\n    private int Step() { return state + 1; }\n    public int Run() { state = 1; return Step(); }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S2325").is_empty());
    }

    #[test]
    fn s2696_flags_instance_writes_to_static_fields() {
        let report = analyze_default(
            "class A\n{\n    private static int hits;\n    public void Record() { hits = hits + 1; }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2696");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 4);

        let clean = analyze_default(
            "class B\n{\n    private static int total;\n    public static void Add(int amount) { total += amount; }\n    public static int Current() => total;\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S2696").is_empty());
    }

    #[test]
    fn s3218_flags_inner_statics_shadowing_outer() {
        let report = analyze_default(
            "class Outer\n{\n    private const string Tag = \"o\";\n    class Inner\n    {\n        private const string Tag = \"i\";\n        public string Get() { return Tag; }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3218");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 6);

        let clean = analyze_default(
            "class Outer\n{\n    private const string Tag = \"o\";\n    class Inner\n    {\n        private const string Mark = \"i\";\n        public string Get() { return Mark; }\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S3218").is_empty());
    }

    #[test]
    fn s3398_flags_private_methods_called_only_from_nested_types() {
        let report = analyze_default(
            "class A\n{\n    private int Secret() { return 1; }\n    class Nested\n    {\n        public int Use(A owner) { return owner.Secret(); }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3398");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);

        let clean = analyze_default(
            "class B\n{\n    private int Local() { return 2; }\n    public int Call() { return Local(); }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S3398").is_empty());

        let sibling = analyze_default(
            "class C\n{\n    private int Hidden() { return 3; }\n}\nclass D\n{\n    public int Tap(C c) { return c.Hidden(); }\n}\n",
        );
        assert!(with_key(&sibling, "csharpsquid:S3398").is_empty());
    }

    #[test]
    fn s1168_flags_null_returns_from_collections() {
        let report = analyze_default(
            "class A\n{\n    public List<int> Load()\n    {\n        return null;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1168");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);

        let arrow_report = analyze_default("class C\n{\n    public int[] Make() => null;\n}\n");
        let arrows = with_key(&arrow_report, "csharpsquid:S1168");
        assert_eq!(arrows.len(), 1);
        assert_eq!(arrows[0].range.start.line, 3);

        let clean = analyze_default(
            "class B\n{\n    public List<int> Load()\n    {\n        return new List<int>();\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S1168").is_empty());
    }

    #[test]
    fn s1226_flags_values_overwritten_before_reading() {
        let report = analyze_default(
            "class A\n{\n    public void Run(int start)\n    {\n        start = 0;\n        System.Console.WriteLine(start);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1226");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);

        let catch_report = analyze_default(
            "class C\n{\n    public void Try()\n    {\n        try\n        {\n            Probe();\n        }\n        catch (System.Exception error)\n        {\n            error = null;\n        }\n    }\n}\n",
        );
        let caught = with_key(&catch_report, "csharpsquid:S1226");
        assert_eq!(caught.len(), 1);
        assert_eq!(caught[0].range.start.line, 11);

        let clean = analyze_default(
            "class B\n{\n    public void Run(int start)\n    {\n        if (start > 0)\n        {\n            start = 0;\n        }\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S1226").is_empty());
    }

    #[test]
    fn s1699_flags_constructors_calling_overridable_members() {
        let report = analyze_default(
            "class A\n{\n    public A()\n    {\n        Initialize();\n    }\n\n    protected virtual void Initialize() { }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1699");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);

        let clean = analyze_default(
            "class B\n{\n    public B()\n    {\n        Setup();\n    }\n\n    private void Setup() { }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S1699").is_empty());
    }

    #[test]
    fn s2955_flags_unconstrained_generic_null_comparisons() {
        let report = analyze_default(
            "class A\n{\n    public T Pick<T>(T candidate)\n    {\n        if (candidate == null)\n        {\n            return candidate;\n        }\n        return candidate;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2955");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);

        let clean = analyze_default(
            "class B\n{\n    public T Pick<T>(T candidate) where T : class\n    {\n        if (candidate != null)\n        {\n            return candidate;\n        }\n        return null;\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S2955").is_empty());
    }

    #[test]
    fn s2997_flags_returning_disposable_from_using() {
        let report = analyze_default(
            "class A\n{\n    public System.IO.Stream Open()\n    {\n        using (var stream = new System.IO.MemoryStream())\n        {\n            return stream;\n        }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2997");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);

        let clean = analyze_default(
            "class B\n{\n    public System.IO.Stream Open()\n    {\n        System.IO.Stream kept;\n        using (var stream = new System.IO.MemoryStream())\n        {\n            kept = stream;\n        }\n        return kept;\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S2997").is_empty());
    }

    #[test]
    fn s3063_flags_unconsumed_string_builders() {
        let report = analyze_default(
            "class A\n{\n    public void Build()\n    {\n        var text = new System.Text.StringBuilder();\n        text.Append(\"a\");\n        text.AppendLine(\"b\");\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3063");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);

        let clean = analyze_default(
            "class B\n{\n    public string Build()\n    {\n        var text = new System.Text.StringBuilder();\n        text.Append(\"a\");\n        return text.ToString();\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S3063").is_empty());
    }

    #[test]
    fn s3172_flags_delegate_subtraction() {
        let report = analyze_default(
            "delegate int Compute(int value);\nclass A\n{\n    private Compute first;\n    private Compute second;\n\n    public int Evaluate(int input)\n    {\n        var combined = first - second;\n        return combined(input);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3172");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 9);

        let clean = analyze_default(
            "delegate int Compute(int value);\nclass A\n{\n    private Compute first;\n    private Compute second;\n\n    public int Evaluate(int input)\n    {\n        var combined = first + second;\n        return combined(input);\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S3172").is_empty());
    }

    #[test]
    fn s3241_flags_fully_discarded_private_results() {
        let report = analyze_default(
            "class A\n{\n    private int Compute() => 42;\n    public void Run()\n    {\n        Compute();\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3241");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);

        let clean = analyze_default(
            "class B\n{\n    private int Compute() => 42;\n    public int Run() => Compute();\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S3241").is_empty());
    }

    #[test]
    fn s3236_flags_explicit_caller_information_arguments() {
        let report = analyze_default(
            "class A\n{\n    private void Trace(string message, [System.Runtime.CompilerServices.CallerMemberName] string member = \"\")\n    {\n        Record(member);\n    }\n\n    private void Record(string member) { }\n}\n\nclass B\n{\n    void Go()\n    {\n        Trace(\"hi\", \"Go\");\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3236");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 15);

        let clean = analyze_default(
            "class A\n{\n    private void Trace(string message, [System.Runtime.CompilerServices.CallerMemberName] string member = \"\")\n    {\n        Record(member);\n    }\n\n    private void Record(string member) { }\n}\n\nclass B\n{\n    void Go()\n    {\n        Trace(\"hi\");\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S3236").is_empty());
    }

    #[test]
    fn s3366_flags_this_escaping_constructors() {
        let report = analyze_default(
            "class A\n{\n    public A()\n    {\n        System.Console.WriteLine(this);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3366");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);

        let clean = analyze_default(
            "class B\n{\n    private int state;\n    public B()\n    {\n        state = this.state;\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S3366").is_empty());
    }

    #[test]
    fn s3263_flags_static_initialization_order_dependencies() {
        let report = analyze_default(
            "class A\n{\n    private static int first = second + 1;\n    private static int second = 5;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3263");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);

        let clean = analyze_default(
            "class B\n{\n    private static int second = 5;\n    private static int first = second + 1;\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S3263").is_empty());
    }

    #[test]
    fn s3265_flags_bitwise_operations_on_non_flags_enums() {
        let report = analyze_default(
            "enum Color\n{\n    Red,\n    Green\n}\nclass A\n{\n    public int Combine(Color left, Color right)\n    {\n        return left | right;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3265");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 10);

        let clean = analyze_default(
            "[Flags]\nenum Mode\n{\n    Read,\n    Write\n}\nclass B\n{\n    public int Combine(Mode left, Mode right)\n    {\n        return left | right;\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S3265").is_empty());
    }

    #[test]
    fn s3443_flags_gettype_on_type_instances() {
        let report = analyze_default(
            "class A\n{\n    public void Inspect(object value)\n    {\n        var kind = value.GetType().GetType();\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3443");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);

        let clean = analyze_default(
            "class B\n{\n    public void Inspect(object value)\n    {\n        var kind = value.GetType();\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S3443").is_empty());
    }

    #[test]
    fn s3900_flags_unvalidated_nullable_public_parameters() {
        let report = analyze_default(
            "class A\n{\n    public int Measure(string? input)\n    {\n        return input.Length;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3900");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);

        let clean = analyze_default(
            "class B\n{\n    public int Measure(string? input)\n    {\n        if (input == null)\n        {\n            return 0;\n        }\n        return input.Length;\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S3900").is_empty());
    }

    #[test]
    fn s3997_flags_string_overloads_not_delegating_to_uri() {
        let report = analyze_default(
            "class A\n{\n    public System.Uri Parse(System.Uri value)\n    {\n        return value;\n    }\n\n    public System.Uri Parse(string text)\n    {\n        return System.Text.RegularExpressions.Regex.Unescape(text);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3997");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 8);

        let clean = analyze_default(
            "class A\n{\n    public System.Uri Parse(System.Uri value)\n    {\n        return value;\n    }\n\n    public System.Uri Parse(string text)\n    {\n        return new System.Uri(text);\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S3997").is_empty());
    }

    #[test]
    fn s4002_flags_finalizers_on_disposable_types() {
        let report = analyze_default(
            "class A : System.IDisposable\n{\n    public void Dispose() { }\n\n    ~A()\n    {\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4002");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);

        let clean =
            analyze_default("class B : System.IDisposable\n{\n    public void Dispose() { }\n}\n");
        assert!(with_key(&clean, "csharpsquid:S4002").is_empty());
    }

    #[test]
    fn s4275_flags_accessors_touching_different_fields() {
        let report = analyze_default(
            "class A\n{\n    private string first;\n    private string second;\n\n    public string Value\n    {\n        get { return first; }\n        set { second = value; }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4275");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 6);

        let clean = analyze_default(
            "class B\n{\n    private string first;\n\n    public string Value\n    {\n        get { return first; }\n        set { first = value; }\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S4275").is_empty());
    }

    #[test]
    fn s127_flags_for_bodies_writing_condition_names() {
        let violating = analyze_default(
            "class C {\n    void M(int size) {\n        int sum = 0;\n        for (int i = 0; i < size; i++) {\n            sum += i;\n            size = 3;\n        }\n    }\n}\n",
        );
        let flagged = with_key(&violating, "csharpsquid:S127");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 4);

        let clean = analyze_default(
            "class C {\n    void M(int size) {\n        int sum = 0;\n        for (int i = 0; i < size; i++) {\n            sum += i;\n        }\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S127").is_empty());
    }

    #[test]
    fn s1751_flags_loops_ending_in_an_unconditional_exit() {
        let violating = analyze_default(
            "class C {\n    void M(bool ready) {\n        while (ready) {\n            Pump();\n            break;\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S1751").len(), 1);

        let clean = analyze_default(
            "class C {\n    void M(bool ready) {\n        while (ready) {\n            Pump();\n        }\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S1751").is_empty());
    }

    #[test]
    fn s1854_flags_stores_masked_before_any_read() {
        let violating = analyze_default(
            "class C {\n    void M() {\n        int total = 1;\n        total = 2;\n        Log(total);\n    }\n}\n",
        );
        let flagged = with_key(&violating, "csharpsquid:S1854");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);

        let clean = analyze_default(
            "class C {\n    void M() {\n        int total = Compute();\n        Log(total);\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S1854").is_empty());
    }

    #[test]
    fn s2123_flags_increments_overwritten_before_any_read() {
        let violating = analyze_default(
            "class C {\n    void M() {\n        int count = 1;\n        count++;\n        count = 5;\n        Use(count);\n    }\n}\n",
        );
        let flagged = with_key(&violating, "csharpsquid:S2123");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 4);

        let clean = analyze_default(
            "class C {\n    void M() {\n        int count = 1;\n        count++;\n        Use(count);\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S2123").is_empty());
    }

    #[test]
    fn s2077_flags_dynamically_composed_sql_text() {
        let violating = analyze_default(
            "class C {\n    void M(string name) {\n        var query = \"SELECT * FROM U WHERE N = '\" + name + \"'\";\n        var command = new SqlCommand(query, connection);\n        command.ExecuteReader();\n    }\n}\n",
        );
        let flagged = with_key(&violating, "csharpsquid:S2077");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 4);

        let clean = analyze_default(
            "class C {\n    void M() {\n        var query = \"SELECT 1\";\n        var command = new SqlCommand(query, connection);\n        command.ExecuteReader();\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S2077").is_empty());
    }

    #[test]
    fn s2190_flags_escape_free_true_loops_and_bare_tail_recursion() {
        let violating = analyze_default(
            "class C {\n    void Spin() {\n        while (true) {\n            Turn();\n        }\n    }\n    void Fall() {\n        Fall();\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S2190").len(), 2);

        let clean = analyze_default(
            "class C {\n    void Spin(bool done) {\n        while (true) {\n            if (done) {\n                break;\n            }\n            Turn();\n        }\n    }\n    int Fact(int n) {\n        if (n <= 1) {\n            return 1;\n        }\n        return Fact(n - 1);\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S2190").is_empty());
    }

    #[test]
    fn s2222_flags_monitor_exits_outside_finally_blocks() {
        let violating = analyze_default(
            "class C {\n    void M(object gate) {\n        Monitor.Enter(gate);\n        try {\n            Work();\n            Monitor.Exit(gate);\n        } catch (System.IO.IOException) {\n        }\n    }\n}\n",
        );
        let flagged = with_key(&violating, "csharpsquid:S2222");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);

        let clean = analyze_default(
            "class C {\n    void M(object gate) {\n        Monitor.Enter(gate);\n        try {\n            Work();\n        } finally {\n            Monitor.Exit(gate);\n        }\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S2222").is_empty());
    }

    #[test]
    fn s2251_flags_counters_moving_against_their_bound() {
        let violating = analyze_default(
            "class C {\n    void M() {\n        for (int i = 10; i > 0; i++) {\n            Tick();\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S2251").len(), 1);

        let clean = analyze_default(
            "class C {\n    void M() {\n        for (int i = 0; i < 10; i++) {\n            Tick();\n        }\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S2251").is_empty());
    }

    #[test]
    fn s2252_flags_conditions_false_at_entry() {
        let violating = analyze_default(
            "class C {\n    void M() {\n        for (int i = 10; i < 5; i++) {\n            Tick();\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S2252").len(), 1);

        let clean = analyze_default(
            "class C {\n    void M() {\n        for (int i = 0; i < 5; i++) {\n            Tick();\n        }\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S2252").is_empty());
    }

    #[test]
    fn s2259_flags_dereferences_of_known_null_locals() {
        let violating = analyze_default(
            "class C {\n    void M() {\n        string s = null;\n        Log(s.Length);\n    }\n}\n",
        );
        let flagged = with_key(&violating, "csharpsquid:S2259");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 4);

        let guarded = analyze_default(
            "class C {\n    void M() {\n        string t = null;\n        if (t != null) {\n            Log(t.Length);\n        }\n    }\n}\n",
        );
        assert!(with_key(&guarded, "csharpsquid:S2259").is_empty());
    }

    #[test]
    fn s2583_flags_literal_false_conditions() {
        let violating = analyze_default(
            "class C {\n    void M() {\n        if (false) {\n            Dead();\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S2583").len(), 1);

        let clean = analyze_default(
            "class C {\n    void M(bool ready) {\n        if (ready) {\n            Run();\n        }\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S2583").is_empty());
    }

    #[test]
    fn s2589_flags_boolean_literals_next_to_short_circuit_operators() {
        let violating = analyze_default(
            "class C {\n    void M(bool ready) {\n        if (ready && true) {\n            Go();\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S2589").len(), 1);

        let clean = analyze_default(
            "class C {\n    void M(bool ready, bool set) {\n        if (ready && set) {\n            Go();\n        }\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S2589").is_empty());
    }

    #[test]
    fn s2674_flags_discarded_stream_read_results() {
        let violating = analyze_default(
            "class C {\n    void M(System.IO.Stream stream) {\n        var buffer = new byte[16];\n        stream.Read(buffer, 0, 16);\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S2674").len(), 1);

        let clean = analyze_default(
            "class C {\n    void M(System.IO.Stream stream) {\n        var buffer = new byte[16];\n        var count = stream.Read(buffer, 0, 16);\n        Log(count);\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S2674").is_empty());
    }

    #[test]
    fn s3353_flags_literal_locals_that_never_change() {
        let violating = analyze_default(
            "class C {\n    void M() {\n        int retries = 3;\n        Attempt(retries);\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S3353").len(), 1);

        let rewritten = analyze_default(
            "class C {\n    void M(int next) {\n        int retries = 3;\n        retries = next;\n        Attempt(retries);\n    }\n}\n",
        );
        assert!(with_key(&rewritten, "csharpsquid:S3353").is_empty());
    }

    #[test]
    fn s3440_flags_comparisons_with_the_value_just_assigned() {
        let violating = analyze_default(
            "class C {\n    void M() {\n        int limit = Read();\n        limit = 10;\n        if (limit == 10) {\n            Mark();\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S3440").len(), 1);

        let clean = analyze_default(
            "class C {\n    void M() {\n        int limit = 10;\n        if (limit == 9) {\n            Mark();\n        }\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S3440").is_empty());
    }

    #[test]
    fn s3655_flags_value_access_without_hasvalue_guards() {
        let violating = analyze_default(
            "class C {\n    void M(int? maybe) {\n        var width = maybe.Value;\n        Draw(width);\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S3655").len(), 1);

        let clean = analyze_default(
            "class C {\n    void M(int? maybe) {\n        if (maybe.HasValue) {\n            var width = maybe.Value;\n            Draw(width);\n        }\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S3655").is_empty());
    }

    #[test]
    fn s3949_flags_constant_arithmetic_wrapping_int() {
        let violating = analyze_default(
            "class C {\n    void M() {\n        var overflow = int.MaxValue + 1;\n        Log(overflow);\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S3949").len(), 1);

        let clean = analyze_default(
            "class C {\n    void M() {\n        var nearTop = int.MaxValue - 1;\n        Log(nearTop);\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S3949").is_empty());
    }

    #[test]
    fn s3966_flags_objects_disposed_twice() {
        let violating = analyze_default(
            "class C {\n    void M(System.IO.Stream stream) {\n        stream.Dispose();\n        stream.Dispose();\n    }\n}\n",
        );
        let flagged = with_key(&violating, "csharpsquid:S3966");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 4);

        let clean = analyze_default(
            "class C {\n    void M(System.IO.Stream stream) {\n        stream.Dispose();\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S3966").is_empty());
    }

    #[test]
    fn s4158_flags_access_into_provably_empty_creations() {
        let violating = analyze_default(
            "class C {\n    void M() {\n        var first = new int[0][0];\n        Log(first);\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S4158").len(), 1);

        let clean = analyze_default(
            "class C {\n    void M() {\n        var empty = new int[0];\n        Log(empty.Length);\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S4158").is_empty());
    }

    #[test]
    fn s2092_and_s3330_flag_cookies_missing_security_flags() {
        let violating = analyze_default(
            "class C {\n    void M() {\n        var cookie = new HttpCookie(\"session\");\n        Response.Cookies.Add(cookie);\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S2092").len(), 1);
        assert_eq!(with_key(&violating, "csharpsquid:S3330").len(), 1);

        let clean = analyze_default(
            "class C {\n    void M() {\n        var cookie = new HttpCookie(\"session\");\n        cookie.Secure = true;\n        cookie.HttpOnly = true;\n        Response.Cookies.Add(cookie);\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S2092").is_empty());
        assert!(with_key(&clean, "csharpsquid:S3330").is_empty());
    }

    #[test]
    fn s2178_flags_bitwise_combinations_of_boolean_operands() {
        let violating = analyze_default(
            "class C {\n    void M(bool IsReady, bool HasData) {\n        if (IsReady & HasData) {\n            Run();\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S2178").len(), 1);

        let clean = analyze_default(
            "class C {\n    void M(int count, bool isReady) {\n        if (count > 0 && isReady) {\n            Run();\n        }\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S2178").is_empty());
    }

    #[test]
    fn s2612_flags_world_writable_unix_file_modes() {
        let violating = analyze_default(
            "class C {\n    void M(string path) {\n        File.SetUnixFileMode(path, UnixFileMode.OthersWrite);\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S2612").len(), 1);

        let clean = analyze_default(
            "class C {\n    void M(string path) {\n        File.SetUnixFileMode(path, UnixFileMode.UserRead);\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S2612").is_empty());
    }

    #[test]
    fn s2755_flags_dtd_enabled_xml_parsers() {
        let violating = analyze_default(
            "class C {\n    void M() {\n        var settings = new XmlReaderSettings();\n        settings.DtdProcessing = DtdProcessing.Parse;\n        settings.ProhibitDtd = false;\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S2755").len(), 2);

        let clean = analyze_default(
            "class C {\n    void M() {\n        var settings = new XmlReaderSettings();\n        settings.DtdProcessing = DtdProcessing.Ignore;\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S2755").is_empty());
    }

    #[test]
    fn s3011_flags_nonpublic_reflection_lookups() {
        let violating = analyze_default(
            "class C {\n    void M() {\n        var field = typeof(A).GetField(\"secret\", BindingFlags.NonPublic | BindingFlags.Instance);\n        Log(field);\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S3011").len(), 1);

        let clean = analyze_default(
            "class C {\n    void M() {\n        var field = typeof(A).GetField(\"shown\", BindingFlags.Public | BindingFlags.Instance);\n        Log(field);\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S3011").is_empty());
    }

    #[test]
    fn s3925_flags_incomplete_iserializable_implementations() {
        let violating = analyze_default("class Bad : ISerializable {\n}\n");
        assert_eq!(with_key(&violating, "csharpsquid:S3925").len(), 1);

        let clean = analyze_default(
            "class Good : ISerializable {\n    protected Good(SerializationInfo info, StreamingContext context) {\n    }\n    public void GetObjectData(SerializationInfo info, StreamingContext context) {\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S3925").is_empty());
    }

    #[test]
    fn s4036_flags_path_resolved_process_starts() {
        let violating = analyze_default(
            "class C {\n    void M() {\n        Process.Start(\"notepad\");\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S4036").len(), 1);

        let clean = analyze_default(
            "class C {\n    void M() {\n        Process.Start(\"C:\\\\tools\\\\notepad.exe\");\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S4036").is_empty());
    }

    #[test]
    fn s4159_flags_exported_contracts_without_implementation() {
        let violating = analyze_default("[Export(typeof(IRepo))]\nclass Bad {\n}\n");
        assert_eq!(with_key(&violating, "csharpsquid:S4159").len(), 1);

        let clean = analyze_default("[Export(typeof(IRepo))]\nclass Good : IRepo {\n}\n");
        assert!(with_key(&clean, "csharpsquid:S4159").is_empty());
    }

    #[test]
    fn s4277_flags_shared_mef_parts_created_with_new() {
        let violating = analyze_default(
            "[Shared]\nclass Part {\n}\nclass User {\n    void M() {\n        var p = new Part();\n        Use(p);\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S4277").len(), 1);

        let clean = analyze_default(
            "class Plain {\n}\nclass User {\n    void M() {\n        var p = new Plain();\n        Use(p);\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S4277").is_empty());
    }

    #[test]
    fn s4433_flags_anonymous_ldap_binds() {
        let violating = analyze_default(
            "class C {\n    void M() {\n        var entry = new DirectoryEntry(\"LDAP://srv\");\n        Use(entry);\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S4433").len(), 1);

        let clean = analyze_default(
            "class C {\n    void M() {\n        var entry = new DirectoryEntry(\"LDAP://srv\", \"user\", \"pass\");\n        Use(entry);\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S4433").is_empty());
    }

    #[test]
    fn s4456_flags_validation_inside_iterators() {
        let violating = analyze_default(
            "class C {\n    System.Collections.Generic.IEnumerable<int> Nums(int[] data) {\n        ArgumentNullException.ThrowIfNull(data);\n        foreach (var x in data) {\n            yield return x;\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S4456").len(), 1);

        let clean = analyze_default(
            "class C {\n    System.Collections.Generic.IEnumerable<int> Nums(int[] data) {\n        foreach (var x in data) {\n            yield return x;\n        }\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S4456").is_empty());
    }

    #[test]
    fn s4457_flags_validation_after_the_first_await() {
        let violating = analyze_default(
            "class C {\n    async System.Threading.Tasks.Task WorkAsync(string name) {\n        await SendAsync();\n        ArgumentNullException.ThrowIfNull(name);\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S4457").len(), 1);

        let clean = analyze_default(
            "class C {\n    async System.Threading.Tasks.Task WorkAsync(string name) {\n        ArgumentNullException.ThrowIfNull(name);\n        await SendAsync();\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S4457").is_empty());
    }

    #[test]
    fn s6563_flags_local_now_recorded_into_instant_named_targets() {
        let violating = analyze_default(
            "class C {\n    void M() {\n        var modified = DateTime.Now;\n        Log(modified);\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S6563").len(), 1);

        let clean = analyze_default(
            "class C {\n    void M() {\n        var modified = DateTime.UtcNow;\n        Log(modified);\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S6563").is_empty());
    }

    #[test]
    fn s6566_flags_datetime_stores_into_datetimeoffset_targets() {
        let violating = analyze_default(
            "class C {\n    DateTimeOffset created;\n    void M() {\n        created = DateTime.Now;\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S6566").len(), 1);

        let clean = analyze_default(
            "class C {\n    DateTimeOffset created;\n    void M() {\n        created = DateTimeOffset.Now;\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S6566").is_empty());
    }
    #[test]
    fn s4055_flags_literals_in_localizable_ui_members() {
        let violating = analyze_default(
            "class Form1 : Form {\n    void M() {\n        lbl.Text = \"hello\";\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S4055").len(), 1);
        let clean = analyze_default(
            "class Form1 : Form {\n    void M() {\n        lbl.Text = LoadResource();\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S4055").is_empty());
    }

    #[test]
    fn s4057_flags_culture_less_convert_calls() {
        let violating = analyze_default(
            "class C {\n    void M(string text) {\n        var n = Convert.ToInt32(text);\n        Log(n);\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S4057").len(), 1);
        let clean = analyze_default(
            "class C {\n    void M(string text) {\n        var n = Convert.ToInt32(text, CultureInfo.InvariantCulture);\n        Log(n);\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S4057").is_empty());
    }

    #[test]
    fn s4226_flags_extensions_next_to_extended_types() {
        let violating = analyze_default(
            "class Repo {\n}\nstatic class Extensions {\n    public static int Count2(this Repo repo) => 1;\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S4226").len(), 1);
        let clean = analyze_default(
            "static class Extensions {\n    public static int Count2(this string s) => 1;\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S4226").is_empty());
    }

    #[test]
    fn s4583_flags_begin_invoke_without_end_invoke() {
        let violating = analyze_default(
            "class C {\n    void M(Handler d) {\n        d.BeginInvoke(Callback(), null);\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S4583").len(), 1);
        let clean = analyze_default(
            "class C {\n    void M(Handler d) {\n        d.BeginInvoke(Callback(), null);\n        d.EndInvoke(null);\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S4583").is_empty());
    }

    #[test]
    fn s4830_flags_certificate_callbacks_accepting_everything() {
        let violating = analyze_default(
            "class C {\n    void M() {\n        ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) => true;\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S4830").len(), 1);
        let clean = analyze_default(
            "class C {\n    void M() {\n        ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) => errors == null;\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S4830").is_empty());
    }

    #[test]
    fn s5034_flags_value_tasks_consumed_twice() {
        let violating = analyze_default(
            "class C {\n    void M() {\n        System.Threading.Tasks.ValueTask<int> pending = FetchAsync();\n        var a = await pending;\n        var b = await pending;\n        Log(a, b);\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S5034").len(), 1);
        let clean = analyze_default(
            "class C {\n    void M() {\n        System.Threading.Tasks.ValueTask<int> pending = FetchAsync();\n        var a = await pending;\n        Log(a);\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S5034").is_empty());
    }

    #[test]
    fn s6377_flags_discarded_signature_checks() {
        let violating = analyze_default(
            "class C {\n    void M(SignedXml doc) {\n        doc.CheckSignature(\"cert\");\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S6377").len(), 1);
        let clean = analyze_default(
            "class C {\n    void M(SignedXml doc) {\n        var ok = doc.CheckSignature(\"cert\");\n        Log(ok);\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S6377").is_empty());
    }

    #[test]
    fn s6668_flags_exceptions_passed_after_the_template() {
        let violating = analyze_default(
            "class C {\n    void M(ILogger logger, string name) {\n        try {\n            Work(name);\n        } catch (System.Exception ex) {\n            logger.LogError(\"Failed for {Name}\", name, ex);\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S6668").len(), 1);
        let clean = analyze_default(
            "class C {\n    void M(ILogger logger, string name) {\n        try {\n            Work(name);\n        } catch (System.Exception ex) {\n            logger.LogError(ex, \"Failed for {Name}\", name);\n        }\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S6668").is_empty());
    }

    #[test]
    fn s6781_flags_hardcoded_jwt_signing_keys() {
        let violating = analyze_default(
            "class C {\n    void M() {\n        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(\"hardcoded-secret\"));\n        Use(key);\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S6781").len(), 1);
        let clean = analyze_default(
            "class C {\n    void M(byte[] configKey) {\n        var key = new SymmetricSecurityKey(configKey);\n        Use(key);\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S6781").is_empty());
    }

    #[test]
    fn s6803_flags_query_binding_without_routes() {
        let violating = analyze_default(
            "class FilterView {\n    [SupplyParameterFromQuery]\n    public string Query { get; set; }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S6803").len(), 1);
        let clean = analyze_default(
            "[Route(\"/filter\")]\nclass FilterViewRouted {\n    [SupplyParameterFromQuery]\n    public string Query { get; set; }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S6803").is_empty());
    }

    #[test]
    fn s6964_flags_value_type_controller_inputs() {
        let violating = analyze_default(
            "[ApiController]\nclass SaveController {\n    [HttpPost]\n    public void Save(int count) {\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S6964").len(), 1);
        let clean = analyze_default(
            "[ApiController]\nclass SaveControllerNullable {\n    [HttpPost]\n    public void Save(int? count) {\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S6964").is_empty());
    }

    #[test]
    fn s6966_flags_discarded_async_calls() {
        let violating =
            analyze_default("class C {\n    void M() {\n        SendAsync();\n    }\n}\n");
        assert_eq!(with_key(&violating, "csharpsquid:S6966").len(), 1);
        let clean = analyze_default(
            "class C {\n    async void M() {\n        await SendAsync();\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S6966").is_empty());
    }

    #[test]
    fn s7131_flags_reader_writer_locks_without_matching_release() {
        let violating = analyze_default(
            "class C {\n    void M(Lock gate) {\n        gate.AcquireWriterLock(0);\n        Work();\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S7131").len(), 1);
        let clean = analyze_default(
            "class C {\n    void M(Lock gate) {\n        gate.AcquireWriterLock(0);\n        Work();\n        gate.ReleaseWriterLock();\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S7131").is_empty());
    }

    #[test]
    fn s7133_flags_monitors_never_released_in_the_member() {
        let violating = analyze_default(
            "class C {\n    void A(object gate) {\n        Monitor.Enter(gate);\n        Work();\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S7133").len(), 1);
        let clean = analyze_default(
            "class C {\n    void A(object gate) {\n        Monitor.Enter(gate);\n        try {\n            Work();\n        } finally {\n            Monitor.Exit(gate);\n        }\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S7133").is_empty());
    }

    #[test]
    fn s2365_flags_getters_that_copy_collections() {
        let violating = analyze_default(
            "class C {\n    private System.Collections.Generic.List<int> items = new System.Collections.Generic.List<int>();\n    public System.Collections.Generic.List<int> Items {\n        get { return items.ToList(); }\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S2365").len(), 1);
        let clean = analyze_default(
            "class D {\n    private System.Collections.Generic.List<int> items = new System.Collections.Generic.List<int>();\n    public System.Collections.Generic.List<int> Items {\n        get { return items; }\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S2365").is_empty());
    }
    #[test]
    fn s6602_flags_first_or_default_on_list_receivers() {
        let violating = analyze_default(
            "class C {\n    void M(System.Collections.Generic.List<int> data) {\n        var hit = data.FirstOrDefault(x => x > 0);\n        Log(hit);\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S6602").len(), 1);
        let clean = analyze_default(
            "class C {\n    void M(int[] data) {\n        var hit = data.FirstOrDefault(x => x > 0);\n        Log(hit);\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S6602").is_empty());
    }

    #[test]
    fn s6603_flags_all_on_list_receivers() {
        let violating = analyze_default(
            "class C {\n    System.Collections.Generic.List<int> data = new System.Collections.Generic.List<int>();\n    bool M() => data.All(x => x > 0);\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S6603").len(), 1);
        let clean = analyze_default(
            "class C {\n    System.Collections.Generic.HashSet<int> data = new System.Collections.Generic.HashSet<int>();\n    bool M() => data.All(x => x > 0);\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S6603").is_empty());
    }

    #[test]
    fn s6605_flags_any_on_list_receivers() {
        let violating = analyze_default(
            "class C {\n    void M(System.Collections.Generic.IList<int> data) {\n        if (data.Any(x => x < 0)) {\n            Warn();\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S6605").len(), 1);
        let clean = analyze_default(
            "class C {\n    void M(System.Collections.Generic.List<int> data) {\n        if (data.Contains(3)) {\n            Warn();\n        }\n    }\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S6605").is_empty());
    }

    #[test]
    fn s6608_flags_enumerable_indexing_on_list_receivers() {
        let violating = analyze_default(
            "class C {\n    System.Collections.Generic.List<int> data = new System.Collections.Generic.List<int>();\n    int M() => data.First();\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S6608").len(), 1);
        let clean = analyze_default(
            "class C {\n    int M(System.Collections.Generic.List<int> data) => data[0];\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S6608").is_empty());
    }

    #[test]
    fn s6609_flags_min_max_extensions_on_sorted_sets() {
        let violating = analyze_default(
            "class C {\n    System.Collections.Generic.SortedSet<int> values = new System.Collections.Generic.SortedSet<int>();\n    int M() => values.Min();\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S6609").len(), 1);
        let clean = analyze_default(
            "class C {\n    int M(System.Collections.Generic.SortedSet<int> values) => values.Min;\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S6609").is_empty());
    }

    #[test]
    fn s6613_flags_first_last_extensions_on_linked_lists() {
        let violating = analyze_default(
            "class C {\n    System.Collections.Generic.LinkedList<int> chain = new System.Collections.Generic.LinkedList<int>();\n    int M() => chain.First();\n}\n",
        );
        assert_eq!(with_key(&violating, "csharpsquid:S6613").len(), 1);
        let clean = analyze_default(
            "class C {\n    System.Collections.Generic.LinkedList<int> chain = new System.Collections.Generic.LinkedList<int>();\n    int M() => chain.First.Value;\n}\n",
        );
        assert!(with_key(&clean, "csharpsquid:S6613").is_empty());
    }
}
