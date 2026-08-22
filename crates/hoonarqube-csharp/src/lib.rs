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
}
