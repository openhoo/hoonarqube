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
/// `csharpsquid:S6669`, and the `csharpsquid:S1451` header knobs).
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
}
