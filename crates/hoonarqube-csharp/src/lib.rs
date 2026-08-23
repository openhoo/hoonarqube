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
/// defaults.
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

/// Gathers every Tier-A4/A5 structural, function-metric, and expression
/// pattern issue.
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
            "class A\n{\n    int X;\n}\n",
            CsLanguage::CSharp,
            &AnalyzerOptions::default(),
        );
        assert_eq!(report.language, "csharpsquid");
        assert!(report.issues.is_empty());
        assert_eq!(report.metrics.lines, 4);
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
}
