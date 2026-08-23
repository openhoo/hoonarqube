//! Tolerant Python analyzer lowering starter-rule findings into `hoonarqube-ir`.
//!
//! The crate parses Python with the embedded Ruff parser and lowers its checks
//! into [`hoonarqube_ir::FileReport`]s. Severity and type always resolve through
//! the frozen `hoonarqube-catalog` catalog via [`hoonarqube_ir::Issue::rule_key`];
//! they are deliberately never duplicated here.

use std::path::PathBuf;

use hoonarqube_ir::Issue;
use ruff_python_ast::token::TokenKind;
use ruff_python_ast::{ExceptHandler, Expr, ModModule, PySourceType, Stmt};
use ruff_python_parser::{Parsed, parse_unchecked_source};
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange, TextSize};

/// Knobs for the Python analyzer; defaults mirror the frozen catalog
/// `ParameterFact` defaults (`maximumLineLength` default `120`,
/// `maximumLinesOfCode` default `1000`, `maximumFunctionParameters` default
/// `13`, `maximumReturnStatements` default `3`, `maximumFunctionLength`
/// default `100`, `maximumNestingDepth` default `4`,
/// `maximumCognitiveComplexity` default `15`, complexity defaults `200`/`200`/`15`).
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
    sort_issues(&mut issues);

    hoonarqube_ir::FileReport {
        path,
        language: "python".to_string(),
        issues,
        metrics: file_metrics(&parsed, source, &index),
    }
}

fn parse(source: &str) -> Parsed<ModModule> {
    parse_unchecked_source(source, PySourceType::Python)
}

fn to_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn to_pos(offset: TextSize, index: &LineIndex, source: &str) -> hoonarqube_ir::Pos {
    let location = index.line_column(offset, source);
    hoonarqube_ir::Pos {
        line: to_u32(location.line.get()),
        column: to_u32(location.column.to_zero_indexed()),
    }
}

fn to_range(range: TextRange, index: &LineIndex, source: &str) -> hoonarqube_ir::Range {
    hoonarqube_ir::Range {
        start: to_pos(range.start(), index, source),
        end: to_pos(range.end(), index, source),
    }
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

/// Lines whose byte interval intersects `range`; multi-line tokens such as
/// triple-quoted strings legitimately span several lines.
fn covered_lines<'a>(
    range: TextRange,
    index: &'a LineIndex,
    source: &'a str,
) -> impl Iterator<Item = u32> + 'a {
    let first = to_u32(
        index
            .line_column(range.start(), source)
            .line
            .to_zero_indexed(),
    );
    let slice = &source[range];
    // A newline transitions to the next line only when characters follow it
    // inside the range; a token ending exactly at a newline stays on its line.
    let mut extra = to_u32(slice.matches('\n').count());
    if slice.ends_with('\n') && extra > 0 {
        extra -= 1;
    }
    first..=first + extra
}

fn file_metrics(
    parsed: &Parsed<ModModule>,
    source: &str,
    index: &LineIndex,
) -> hoonarqube_ir::FileMetrics {
    let lines = if source.is_empty() {
        0
    } else {
        to_u32(source.lines().count())
    };

    let code_lines: std::collections::BTreeSet<u32> = parsed
        .tokens()
        .iter()
        .filter(|token| !token.kind().is_trivia())
        .flat_map(|token| covered_lines(token.range(), index, source))
        .collect();

    let comment_lines: std::collections::BTreeSet<u32> = parsed
        .tokens()
        .iter()
        .filter(|token| token.kind().is_comment())
        .flat_map(|token| covered_lines(token.range(), index, source))
        .filter(|line| !code_lines.contains(line))
        .collect();

    hoonarqube_ir::FileMetrics {
        lines,
        code_lines: to_u32(code_lines.len()),
        comment_lines: to_u32(comment_lines.len()),
    }
}

fn check_parsing_errors(parsed: &Parsed<ModModule>, index: &LineIndex, source: &str) -> Vec<Issue> {
    parsed
        .errors()
        .iter()
        .map(|error| Issue {
            rule_key: "python:ParsingError".to_string(),
            message: format!("{}", error.error),
            range: to_range(error.location, index, source),
        })
        .collect()
}

fn check_no_sonar(parsed: &Parsed<ModModule>, index: &LineIndex, source: &str) -> Vec<Issue> {
    parsed
        .tokens()
        .iter()
        .filter(|token| token.kind().is_comment())
        .filter(|token| source[token.range()].contains("NOSONAR"))
        .map(|token| Issue {
            rule_key: "python:NoSonar".to_string(),
            message: "Remove this usage of 'NOSONAR'.".to_string(),
            range: to_range(token.range(), index, source),
        })
        .collect()
}

fn check_line_length(source: &str, options: &AnalyzerOptions) -> Vec<Issue> {
    let maximum = usize::try_from(options.maximum_line_length).unwrap_or(usize::MAX);
    let mut issues = Vec::new();
    for (zero_based, chunk) in source.split_inclusive('\n').enumerate() {
        let line = chunk.trim_end_matches(['\r', '\n']);
        let length = line.chars().count();
        if length > maximum {
            let line_number = to_u32(zero_based) + 1;
            issues.push(Issue {
                rule_key: "python:LineLength".to_string(),
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

fn check_one_statement_per_line(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    check_suite(parsed.syntax().body.as_slice(), &mut issues, index, source);
    issues
}

fn check_suite(
    suite: &[ruff_python_ast::Stmt],
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    let line_of = |stmt: &ruff_python_ast::Stmt| to_pos(stmt.range().start(), index, source).line;

    let mut start = 0;
    while start < suite.len() {
        let first_line = line_of(&suite[start]);
        let mut end = start + 1;
        while end < suite.len() && line_of(&suite[end]) == first_line {
            end += 1;
        }
        for stmt in &suite[start + 1..end] {
            issues.push(Issue {
                rule_key: "python:OneStatementPerLine".to_string(),
                message: "Only one statement per line is allowed.".to_string(),
                range: to_range(stmt.range(), index, source),
            });
        }
        for stmt in &suite[start..end] {
            check_nested_bodies(stmt, issues, index, source);
        }
        start = end;
    }
}

fn check_nested_bodies(
    stmt: &ruff_python_ast::Stmt,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    use ruff_python_ast::{ExceptHandler, Stmt};
    match stmt {
        Stmt::FunctionDef(s) => check_suite(&s.body, issues, index, source),
        Stmt::ClassDef(s) => check_suite(&s.body, issues, index, source),
        Stmt::For(s) => {
            check_suite(&s.body, issues, index, source);
            check_suite(&s.orelse, issues, index, source);
        }
        Stmt::While(s) => {
            check_suite(&s.body, issues, index, source);
            check_suite(&s.orelse, issues, index, source);
        }
        Stmt::If(s) => {
            check_suite(&s.body, issues, index, source);
            for clause in &s.elif_else_clauses {
                check_suite(&clause.body, issues, index, source);
            }
        }
        Stmt::With(s) => check_suite(&s.body, issues, index, source),
        Stmt::Match(s) => {
            for case in &s.cases {
                check_suite(&case.body, issues, index, source);
            }
        }
        Stmt::Try(s) => {
            check_suite(&s.body, issues, index, source);
            for handler in &s.handlers {
                match handler {
                    ExceptHandler::ExceptHandler(handler) => {
                        check_suite(&handler.body, issues, index, source);
                    }
                }
            }
            check_suite(&s.orelse, issues, index, source);
            check_suite(&s.finalbody, issues, index, source);
        }
        _ => {}
    }
}

fn check_call_usage(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    identifier: &str,
    rule_key: &str,
    message: &str,
) -> Vec<Issue> {
    let significant: Vec<&ruff_python_ast::token::Token> = parsed
        .tokens()
        .iter()
        .filter(|token| !token.kind().is_trivia())
        .collect();
    significant
        .windows(2)
        .filter(|pair| {
            pair[0].kind() == TokenKind::Name
                && &source[pair[0].range()] == identifier
                && pair[1].kind() == TokenKind::Lpar
        })
        .map(|pair| Issue {
            rule_key: rule_key.to_string(),
            message: message.to_string(),
            range: to_range(pair[0].range(), index, source),
        })
        .collect()
}

/// python:S113 — file must end with a newline character; empty files exempt.
fn check_ends_with_newline(source: &str) -> Vec<Issue> {
    if source.is_empty() || source.ends_with('\n') {
        return Vec::new();
    }
    let last_line = to_u32(source.split_inclusive('\n').count());
    let length = source.split_inclusive('\n').next_back().map_or(0, |chunk| {
        to_u32(chunk.trim_end_matches('\r').chars().count())
    });
    vec![Issue {
        rule_key: "python:S113".to_string(),
        message: "Add a newline character at the end of this file.".to_string(),
        range: hoonarqube_ir::Range {
            start: hoonarqube_ir::Pos {
                line: last_line,
                column: 0,
            },
            end: hoonarqube_ir::Pos {
                line: last_line,
                column: length,
            },
        },
    }]
}

/// Iterates `(1-based line number, line text without terminators)`.
fn for_each_line(source: &str, mut visit: impl FnMut(u32, &str)) {
    for (zero_based, chunk) in source.split_inclusive('\n').enumerate() {
        let text = chunk.trim_end_matches(['\r', '\n']);
        visit(to_u32(zero_based) + 1, text);
    }
}

/// python:S1131 — lines must not end with whitespace.
fn check_trailing_whitespace(source: &str) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_line(source, |line, text| {
        let content = text.trim_end_matches([' ', '\t']);
        if content.len() < text.len() {
            issues.push(Issue {
                rule_key: "python:S1131".to_string(),
                message: "Remove the trailing whitespaces from this line.".to_string(),
                range: hoonarqube_ir::Range {
                    start: hoonarqube_ir::Pos {
                        line,
                        column: to_u32(content.chars().count()),
                    },
                    end: hoonarqube_ir::Pos {
                        line,
                        column: to_u32(text.chars().count()),
                    },
                },
            });
        }
    });
    issues
}

fn comment_tokens(
    parsed: &Parsed<ModModule>,
) -> impl Iterator<Item = &ruff_python_ast::token::Token> {
    parsed
        .tokens()
        .iter()
        .filter(|token| token.kind() == TokenKind::Comment)
}

const FIXME_TAG: &str = "fixme";
const TODO_TAG: &str = "todo";

/// python:S1134/S1135/S1707 — track FIXME/TODO comments and require a person
/// reference matching `[ ]*\([ _a-zA-Z0-9@.]+\)` right after the tag.
fn check_issue_tags(parsed: &Parsed<ModModule>, index: &LineIndex, source: &str) -> Vec<Issue> {
    let mut issues = Vec::new();
    for comment in comment_tokens(parsed) {
        let text = source[comment.range()].to_lowercase();
        if !text.contains(FIXME_TAG) && !text.contains(TODO_TAG) {
            continue;
        }
        for (key, tag) in [("python:S1134", FIXME_TAG), ("python:S1135", TODO_TAG)] {
            if text.contains(tag) {
                issues.push(Issue {
                    rule_key: key.to_string(),
                    message: format!(
                        "Resolve this {} comment or clarify it with a person reference.",
                        tag.to_uppercase()
                    ),
                    range: to_range(comment.range(), index, source),
                });
            }
        }
        if !has_person_reference(&text) {
            issues.push(Issue {
                rule_key: "python:S1707".to_string(),
                message: "Add a person reference such as '(jane)' to this TODO/FIXME comment."
                    .to_string(),
                range: to_range(comment.range(), index, source),
            });
        }
    }
    issues
}

/// Checks the first TODO/FIXME occurrence in the comment for the person
/// reference pattern `[ ]*\([ _a-zA-Z0-9@.]+\)`.
fn has_person_reference(lowercased_comment: &str) -> bool {
    let Some(tag_pos) = lowercased_comment
        .find(FIXME_TAG)
        .into_iter()
        .chain(lowercased_comment.find(TODO_TAG))
        .min()
    else {
        return true;
    };
    let rest = lowercased_comment[tag_pos..]
        .trim_start_matches(|c: char| c.is_ascii_alphabetic())
        .trim_start_matches(' ');
    let Some(body) = rest.strip_prefix('(').and_then(|r| r.split_once(')')) else {
        return false;
    };
    !body.0.is_empty()
        && body
            .0
            .chars()
            .all(|c| c == '_' || c == ' ' || c == '@' || c == '.' || c.is_ascii_alphanumeric())
}

/// python:S1309 — any `noqa` suppression comment is tracked.
/// python:S7632 — `noqa` comments must use `# noqa: CODE[,CODE...]` with
/// uppercase letter+digit codes.
fn check_noqa_comments(parsed: &Parsed<ModModule>, index: &LineIndex, source: &str) -> Vec<Issue> {
    let mut issues = Vec::new();
    for comment in comment_tokens(parsed) {
        let text = &source[comment.range()];
        if !text.to_lowercase().contains("noqa") {
            continue;
        }
        issues.push(Issue {
            rule_key: "python:S1309".to_string(),
            message: "Do not suppress issues with a 'noqa' comment; fix the issue instead."
                .to_string(),
            range: to_range(comment.range(), index, source),
        });
        if !noqa_format_valid(text) {
            issues.push(Issue {
                rule_key: "python:S7632".to_string(),
                message: "Use the format '# noqa: CODE' with comma-separated uppercase codes."
                    .to_string(),
                range: to_range(comment.range(), index, source),
            });
        }
    }
    issues
}

/// Validates every `noqa` occurrence in the raw comment text against
/// `# noqa` / `# noqa: E501[,F841]`.
fn noqa_format_valid(text: &str) -> bool {
    let lower = text.to_lowercase();
    let mut search_from = 0;
    while let Some(rel) = lower[search_from..].find("noqa") {
        let start = search_from + rel;
        let before = &text[..start];
        let hash_ok = match before.rfind('#') {
            Some(hash_pos) => {
                let gap = &before[hash_pos + 1..];
                !gap.is_empty() && gap.chars().all(|c| c == ' ')
            }
            None => false,
        };
        if !hash_ok {
            return false;
        }
        let after = &text[start + 4..];
        if !(after.is_empty() || after.starts_with('#')) {
            let Some(codes) = after.strip_prefix(':') else {
                return false;
            };
            for code in codes.split(',') {
                let code = code.trim();
                let valid = !code.is_empty()
                    && code
                        .chars()
                        .all(|c: char| c.is_ascii_uppercase() || c.is_ascii_digit())
                    && code.chars().any(|c: char| c.is_ascii_uppercase())
                    && code
                        .find(|c: char| c.is_ascii_digit())
                        .is_some_and(|first_digit| {
                            code[..first_digit]
                                .chars()
                                .all(|c: char| c.is_ascii_uppercase())
                        });
                if !valid {
                    return false;
                }
            }
        }
        search_from = start + 4;
    }
    true
}

fn check_license_header(options: &AnalyzerOptions, source: &str) -> Vec<Issue> {
    let format = options.copyright_header_format.as_str();
    if format.is_empty() {
        return Vec::new();
    }
    let body = source.strip_prefix("#!").map_or(source, |after_shebang| {
        after_shebang
            .split_once('\n')
            .map_or(after_shebang, |n| n.1)
    });
    let trimmed = body.trim_start_matches('\n');
    // Real-world headers are comments; accept an optional `#` marker plus
    // indentation between the format and the file head.
    let unmarked = trimmed
        .strip_prefix('#')
        .map_or(trimmed, |rest| rest.trim_start_matches([' ', '\t']));
    if trimmed.starts_with(format) || unmarked.starts_with(format) {
        return Vec::new();
    }
    vec![Issue {
        rule_key: "python:S1451".to_string(),
        message: "Add or update the copyright header of this file.".to_string(),
        range: hoonarqube_ir::Range {
            start: hoonarqube_ir::Pos { line: 1, column: 0 },
            end: hoonarqube_ir::Pos { line: 1, column: 0 },
        },
    }]
}

/// python:S1578 — module file stem must match
/// `(([a-z_][a-z0-9_]*)|([A-Z][a-zA-Z0-9]+))`.
fn check_module_name(path: &std::path::Path, index: &LineIndex, source: &str) -> Vec<Issue> {
    let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
        return Vec::new();
    };
    if module_name_matches_convention(stem) {
        return Vec::new();
    }
    vec![Issue {
        rule_key: "python:S1578".to_string(),
        message: "Rename this module to comply with the naming convention.".to_string(),
        range: hoonarqube_ir::Range {
            start: to_pos(TextSize::from(0), index, source),
            end: to_pos(TextSize::from(0), index, source),
        },
    }]
}

/// Matches `([a-z_][a-z0-9_]*)|([A-Z][a-zA-Z0-9]+)` without a regex engine.
fn module_name_matches_convention(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if first == '_' || first.is_ascii_lowercase() {
        name.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    } else {
        first.is_ascii_uppercase()
            && name.chars().skip(1).all(|c| c.is_ascii_alphanumeric())
            && name.len() > 1
    }
}

// ---------------------------------------------------------------------------
// Shared helpers for the Tier-A rule battery.
// ---------------------------------------------------------------------------

const PYTHON_KEYWORDS: [&str; 35] = [
    "False", "None", "True", "and", "as", "assert", "async", "await", "break", "class", "continue",
    "def", "del", "elif", "else", "except", "finally", "for", "from", "global", "if", "import",
    "in", "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try", "while",
    "with", "yield",
];

fn is_keyword(text: &str) -> bool {
    PYTHON_KEYWORDS.contains(&text)
}

/// Directly nested statement bodies of a compound statement.
fn child_bodies(stmt: &Stmt) -> Vec<&[Stmt]> {
    match stmt {
        Stmt::FunctionDef(s) => vec![s.body.as_slice()],
        Stmt::ClassDef(s) => vec![s.body.as_slice()],
        Stmt::For(s) => vec![s.body.as_slice(), s.orelse.as_slice()],
        Stmt::While(s) => vec![s.body.as_slice(), s.orelse.as_slice()],
        Stmt::If(s) => {
            let mut bodies = vec![s.body.as_slice()];
            bodies.extend(
                s.elif_else_clauses
                    .iter()
                    .map(|clause| clause.body.as_slice()),
            );
            bodies
        }
        Stmt::With(s) => vec![s.body.as_slice()],
        Stmt::Match(s) => s.cases.iter().map(|case| case.body.as_slice()).collect(),
        Stmt::Try(s) => {
            let mut bodies = vec![
                s.body.as_slice(),
                s.orelse.as_slice(),
                s.finalbody.as_slice(),
            ];
            bodies.extend(s.handlers.iter().map(|handler| match handler {
                ExceptHandler::ExceptHandler(handler) => handler.body.as_slice(),
            }));
            bodies
        }
        _ => Vec::new(),
    }
}

/// Depth-first visit of every statement in the tree.
fn for_each_stmt(stmts: &[Stmt], visit: &mut impl FnMut(&Stmt)) {
    for stmt in stmts {
        visit(stmt);
        for body in child_bodies(stmt) {
            for_each_stmt(body, visit);
        }
    }
}

/// Direct child expressions of an expression. FString/TString interiors are
/// intentionally opaque: their literal parts are not visited.
fn child_exprs(expr: &Expr) -> Vec<&Expr> {
    let mut children: Vec<&Expr> = Vec::new();
    match expr {
        Expr::BoolOp(e) => children.extend(&e.values),
        Expr::Named(e) => {
            children.push(&e.target);
            children.push(&e.value);
        }
        Expr::BinOp(e) => {
            children.push(&e.left);
            children.push(&e.right);
        }
        Expr::UnaryOp(e) => children.push(&e.operand),
        Expr::Lambda(e) => children.push(&e.body),
        Expr::If(e) => {
            children.push(&e.test);
            children.push(&e.body);
            children.push(&e.orelse);
        }
        Expr::Dict(e) => {
            for item in &e.items {
                if let Some(key) = &item.key {
                    children.push(key);
                }
                children.push(&item.value);
            }
        }
        Expr::Set(e) => children.extend(&e.elts),
        Expr::List(e) => children.extend(&e.elts),
        Expr::Tuple(e) => children.extend(&e.elts),
        Expr::ListComp(e) => {
            children.push(&e.elt);
            push_generator_exprs(&e.generators, &mut children);
        }
        Expr::SetComp(e) => {
            children.push(&e.elt);
            push_generator_exprs(&e.generators, &mut children);
        }
        Expr::Generator(e) => {
            children.push(&e.elt);
            push_generator_exprs(&e.generators, &mut children);
        }
        Expr::DictComp(e) => {
            if let Some(key) = &e.key {
                children.push(key);
            }
            children.push(&e.value);
            push_generator_exprs(&e.generators, &mut children);
        }
        Expr::Await(e) => children.push(&e.value),
        Expr::YieldFrom(e) => children.push(&e.value),
        Expr::Yield(e) => children.extend(e.value.as_deref()),
        Expr::Compare(e) => {
            children.push(&e.left);
            children.extend(&e.comparators);
        }
        Expr::Call(e) => {
            children.push(&e.func);
            children.extend(&e.arguments.args);
            children.extend(e.arguments.keywords.iter().map(|keyword| &keyword.value));
        }
        Expr::Attribute(e) => children.push(&e.value),
        Expr::Subscript(e) => {
            children.push(&e.value);
            children.push(&e.slice);
        }
        Expr::Starred(e) => children.push(&e.value),
        Expr::Slice(e) => {
            for bound in [&e.lower, &e.upper, &e.step].into_iter().flatten() {
                children.push(bound);
            }
        }
        _ => {}
    }
    children
}

fn push_generator_exprs<'a>(
    generators: &'a [ruff_python_ast::Comprehension],
    children: &mut Vec<&'a Expr>,
) {
    for generator in generators {
        children.push(&generator.target);
        children.push(&generator.iter);
        children.extend(&generator.ifs);
    }
}

fn for_each_expr(expr: &Expr, visit: &mut impl FnMut(&Expr)) {
    visit(expr);
    for child in child_exprs(expr) {
        for_each_expr(child, visit);
    }
}

/// Visits every expression reachable from a statement tree.
fn for_each_stmt_expr(stmts: &[Stmt], visit: &mut impl FnMut(&Expr)) {
    for_each_stmt(stmts, &mut |stmt| {
        for expr in stmt_exprs(stmt) {
            for_each_expr(expr, visit);
        }
    });
}

/// Top-level expressions carried directly by a statement (decorators,
/// annotations, defaults, tests, targets, values, ...).
fn stmt_exprs(stmt: &Stmt) -> Vec<&Expr> {
    let mut exprs: Vec<&Expr> = Vec::new();
    match stmt {
        Stmt::FunctionDef(s) => {
            for decorator in &s.decorator_list {
                exprs.push(&decorator.expression);
            }
            if let Some(returns) = &s.returns {
                exprs.push(returns);
            }
            push_parameter_exprs(&s.parameters, &mut exprs);
        }
        Stmt::ClassDef(s) => {
            for decorator in &s.decorator_list {
                exprs.push(&decorator.expression);
            }
            if let Some(arguments) = &s.arguments {
                exprs.extend(&arguments.args);
                exprs.extend(arguments.keywords.iter().map(|keyword| &keyword.value));
            }
        }
        Stmt::Return(s) => exprs.extend(s.value.as_deref()),
        Stmt::Delete(s) => exprs.extend(&s.targets),
        Stmt::Assign(s) => {
            exprs.extend(&s.targets);
            exprs.push(&s.value);
        }
        Stmt::AugAssign(s) => {
            exprs.push(&s.target);
            exprs.push(&s.value);
        }
        Stmt::AnnAssign(s) => {
            exprs.push(&s.target);
            exprs.push(&s.annotation);
            exprs.extend(s.value.as_deref());
        }
        Stmt::For(s) => {
            exprs.push(&s.target);
            exprs.push(&s.iter);
        }
        Stmt::While(s) => exprs.push(&s.test),
        Stmt::If(s) => {
            exprs.push(&s.test);
            for clause in &s.elif_else_clauses {
                if let Some(test) = &clause.test {
                    exprs.push(test);
                }
            }
        }
        Stmt::With(s) => {
            for item in &s.items {
                exprs.push(&item.context_expr);
                if let Some(vars) = &item.optional_vars {
                    exprs.push(vars);
                }
            }
        }
        Stmt::Match(s) => {
            exprs.push(&s.subject);
            for case in &s.cases {
                if let Some(guard) = &case.guard {
                    exprs.push(guard);
                }
            }
        }
        Stmt::Raise(s) => {
            exprs.extend(s.exc.as_deref());
            exprs.extend(s.cause.as_deref());
        }
        Stmt::Assert(s) => exprs.push(&s.test),
        Stmt::Expr(s) => exprs.push(&s.value),
        _ => {}
    }
    exprs
}

/// Default values and annotations of a parameter list.
fn push_parameter_exprs<'a>(
    parameters: &'a ruff_python_ast::Parameters,
    exprs: &mut Vec<&'a Expr>,
) {
    for parameter in parameters
        .posonlyargs
        .iter()
        .chain(&parameters.args)
        .chain(&parameters.kwonlyargs)
    {
        if let Some(annotation) = parameter.parameter.annotation.as_deref() {
            exprs.push(annotation);
        }
        if let Some(default) = parameter.default.as_deref() {
            exprs.push(default);
        }
    }
    for bound in [parameters.vararg.as_deref(), parameters.kwarg.as_deref()]
        .into_iter()
        .flatten()
    {
        if let Some(annotation) = bound.annotation.as_deref() {
            exprs.push(annotation);
        }
    }
}

/// Decoded text and source span of every plain string literal in the tree.
/// Bytes literals and f-strings are intentionally not collected.
fn collect_string_contents(stmts: &[Stmt]) -> Vec<(String, TextRange)> {
    let mut contents = Vec::new();
    for_each_stmt_expr(stmts, &mut |expr| {
        if let Expr::StringLiteral(literal) = expr {
            contents.push((string_value_text(&literal.value), literal.range()));
        }
    });
    contents
}

/// Concatenated decoded text of a (possibly implicitly concatenated)
/// string literal value.
fn string_value_text(value: &ruff_python_ast::StringLiteralValue) -> String {
    let mut text = String::new();
    for part in value {
        text.push_str(&part.value);
    }
    text
}

fn shannon_entropy(text: &str) -> f64 {
    let mut counts = [0u32; 256];
    for &byte in text.as_bytes() {
        counts[byte as usize] += 1;
    }
    let total = f64::from(to_u32(text.len()));
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = f64::from(*count) / total;
            -probability * probability.log2()
        })
        .sum()
}

/// Maximal runs of characters satisfying `predicate`.
fn maximal_runs<'a>(
    text: &'a str,
    predicate: impl Fn(char) -> bool + 'a,
) -> impl Iterator<Item = &'a str> + 'a {
    text.split(move |ch| !predicate(ch))
        .filter(|run| !run.is_empty())
}

fn significant_tokens(parsed: &Parsed<ModModule>) -> Vec<&ruff_python_ast::token::Token> {
    parsed
        .tokens()
        .iter()
        .filter(|token| !token.kind().is_trivia())
        .collect()
}

/// Source regions that must be ignored by raw-text scans: comments, string
/// literals, and whole f-string/t-string regions including their interiors.
fn masked_spans(parsed: &Parsed<ModModule>) -> Vec<TextRange> {
    let mut spans = Vec::new();
    let mut depth = 0u32;
    let mut open_region: Option<TextSize> = None;
    for token in parsed.tokens() {
        match token.kind() {
            TokenKind::Comment | TokenKind::String => spans.push(token.range()),
            TokenKind::FStringStart | TokenKind::TStringStart => {
                depth += 1;
                if open_region.is_none() {
                    open_region = Some(token.range().start());
                }
            }
            TokenKind::FStringEnd | TokenKind::TStringEnd => {
                depth = depth.saturating_sub(1);
                if depth == 0
                    && let Some(start) = open_region.take()
                {
                    spans.push(TextRange::new(start, token.range().end()));
                }
            }
            _ => {}
        }
    }
    spans
}

/// `(absolute byte offset, text)` for the source outside all masked spans.
fn unmasked_segments<'a>(parsed: &'a Parsed<ModModule>, source: &'a str) -> Vec<(usize, &'a str)> {
    let mut spans = masked_spans(parsed);
    spans.sort_by_key(|range| (u32::from(range.start()), u32::from(range.end())));
    let mut segments = Vec::new();
    let mut cursor = 0usize;
    for range in spans {
        let start = usize::try_from(u32::from(range.start())).unwrap_or(0);
        let end = usize::try_from(u32::from(range.end())).unwrap_or(0);
        if start > cursor {
            segments.push((cursor, &source[cursor..start]));
        }
        cursor = cursor.max(end);
    }
    if cursor < source.len() {
        segments.push((cursor, &source[cursor..]));
    }
    segments
}

// ---------------------------------------------------------------------------
// python:S1313 — hardcoded IP addresses in string literals.
// ---------------------------------------------------------------------------

fn check_hardcoded_ips(parsed: &Parsed<ModModule>, index: &LineIndex, source: &str) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (text, range) in collect_string_contents(parsed.syntax().body.as_slice()) {
        if !ip_addresses(&text).is_empty() {
            issues.push(Issue {
                rule_key: "python:S1313".to_string(),
                message: "Make this IP address configurable.".to_string(),
                range: to_range(range, index, source),
            });
        }
    }
    issues
}

/// Extracts IPv4 and IPv6-looking candidates; loopback, wildcard, and
/// broadcast IPv4 addresses are exempt per the RSPEC.
fn ip_addresses(text: &str) -> Vec<String> {
    let mut found: Vec<String> = maximal_runs(text, |ch| ch.is_ascii_digit() || ch == '.')
        .filter_map(parse_ipv4)
        .collect();
    found.extend(
        maximal_runs(text, |ch| ch.is_ascii_hexdigit() || ch == ':').filter_map(parse_ipv6),
    );
    found.sort();
    found.dedup();
    found
}

fn parse_ipv4(run: &str) -> Option<String> {
    const EXEMPT: [&str; 3] = ["0.0.0.0", "127.0.0.1", "255.255.255.255"];
    let octets: Vec<&str> = run.split('.').collect();
    let valid = octets.len() == 4
        && octets.iter().all(|octet| {
            !octet.is_empty()
                && octet.len() <= 3
                && octet.bytes().all(|byte| byte.is_ascii_digit())
                && octet.parse::<u16>().is_ok_and(|value| value <= 255)
        });
    if valid && !EXEMPT.contains(&run) {
        Some(run.to_string())
    } else {
        None
    }
}

fn parse_ipv6(run: &str) -> Option<String> {
    if run == "::" || run == "::1" {
        return None;
    }
    let groups: Vec<&str> = run.split(':').filter(|group| !group.is_empty()).collect();
    let valid = groups.len() >= 2
        && groups
            .iter()
            .all(|group| group.len() <= 4 && group.bytes().all(|byte| byte.is_ascii_hexdigit()));
    if valid { Some(run.to_string()) } else { None }
}

// ---------------------------------------------------------------------------
// python:S5332 — cleartext protocols in string literals.
// ---------------------------------------------------------------------------

fn check_cleartext_protocols(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    const CLEARTEXT_SCHEMES: [&str; 3] = ["http://", "ftp://", "telnet://"];
    const SAFE_HOSTS: [&str; 5] = [
        "localhost",
        "127.0.0.1",
        "::1",
        "example.org",
        "example.com",
    ];
    let mut issues = Vec::new();
    for (text, range) in collect_string_contents(parsed.syntax().body.as_slice()) {
        let mut flagged = false;
        for scheme in CLEARTEXT_SCHEMES {
            let mut search = 0usize;
            while let Some(relative) = text[search..].find(scheme) {
                let start = search + relative + scheme.len();
                let host = text[start..]
                    .split(['/', ':', '?', '#'])
                    .next()
                    .unwrap_or_default();
                let safe = SAFE_HOSTS.contains(&host)
                    || host.ends_with(".example.org")
                    || host.ends_with(".example.com");
                if !safe && !host.is_empty() {
                    flagged = true;
                }
                search = start;
            }
        }
        if flagged {
            issues.push(Issue {
                rule_key: "python:S5332".to_string(),
                message:
                    "Use an encrypted protocol such as HTTPS instead of this cleartext connection."
                        .to_string(),
                range: to_range(range, index, source),
            });
        }
    }
    issues
}

// ---------------------------------------------------------------------------
// python:S2068 — hard-coded credentials.
// ---------------------------------------------------------------------------

const CREDENTIAL_WORDS: [&str; 4] = ["password", "passwd", "pwd", "passphrase"];

fn check_hardcoded_credentials(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let (targets, value) = match stmt {
            Stmt::Assign(s) => (s.targets.as_slice(), Some(&*s.value)),
            Stmt::AnnAssign(s) => (std::slice::from_ref(&*s.target), s.value.as_deref()),
            _ => return,
        };
        let Some(Expr::StringLiteral(literal)) = value else {
            return;
        };
        if literal.value.is_empty() {
            return;
        }
        for target in targets {
            if let Expr::Name(name) = target
                && name_words(name.id.as_str()).any(|word| CREDENTIAL_WORDS.contains(&word))
            {
                issues.push(Issue {
                    rule_key: "python:S2068".to_string(),
                    message: "Review this potentially hard-coded credentials.".to_string(),
                    range: to_range(name.range(), index, source),
                });
            }
        }
    });
    for (text, range) in collect_string_contents(parsed.syntax().body.as_slice()) {
        if embeds_credential(&text) {
            issues.push(Issue {
                rule_key: "python:S2068".to_string(),
                message: "Review this potentially hard-coded credentials.".to_string(),
                range: to_range(range, index, source),
            });
        }
    }
    issues
}

fn name_words(name: &str) -> impl Iterator<Item = &str> {
    name.split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
}

/// Matches `(?i)(password|passwd|pwd|passphrase)\s*[=:]\s*\S` inside a
/// string literal.
fn embeds_credential(text: &str) -> bool {
    let lower = text.to_lowercase();
    CREDENTIAL_WORDS.iter().any(|word| {
        lower.match_indices(word).any(|(position, _)| {
            let rest = lower[position + word.len()..].trim_start_matches([' ', '\t']);
            let Some(separator) = rest.chars().next() else {
                return false;
            };
            (separator == '=' || separator == ':')
                && rest[1..]
                    .trim_start_matches([' ', '\t'])
                    .chars()
                    .next()
                    .is_some_and(|ch| !ch.is_whitespace())
        })
    })
}

// ---------------------------------------------------------------------------
// python:S6418 / python:S6437 — hard-coded secrets.
// ---------------------------------------------------------------------------

const SECRET_ENTROPY_THRESHOLD: f64 = 3.0;
const SECRET_HIGH_ENTROPY_THRESHOLD: f64 = 4.5;

fn check_hardcoded_secrets(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let value = match stmt {
            Stmt::Assign(s) => Some(&*s.value),
            Stmt::AnnAssign(s) => s.value.as_deref(),
            _ => None,
        };
        let Some(Expr::StringLiteral(literal)) = value else {
            return;
        };
        let text = string_value_text(&literal.value);
        if text.is_empty() {
            return;
        }
        let named = stmt_targets(stmt)
            .any(|target| matches!(target, Expr::Name(name) if is_secret_name(name.id.as_str())));
        let entropy = shannon_entropy(&text);
        let secret_shaped = named && (entropy > SECRET_ENTROPY_THRESHOLD || text.len() >= 16);
        if secret_shaped {
            issues.push(Issue {
                rule_key: "python:S6418".to_string(),
                message: "Review this potentially hard-coded secret.".to_string(),
                range: to_range(literal.range(), index, source),
            });
        }
        let mixed = text.chars().any(|ch| ch.is_ascii_uppercase())
            && text.chars().any(|ch| ch.is_ascii_lowercase())
            && text.chars().any(|ch| ch.is_ascii_digit());
        if secret_shaped || (entropy >= SECRET_HIGH_ENTROPY_THRESHOLD && text.len() >= 20 && mixed)
        {
            issues.push(Issue {
                rule_key: "python:S6437".to_string(),
                message: "Revoke and replace this hard-coded credential with one stored securely."
                    .to_string(),
                range: to_range(literal.range(), index, source),
            });
        }
    });
    issues
}

fn is_secret_name(name: &str) -> bool {
    let normalized: String = name
        .to_lowercase()
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect();
    ["apikey", "auth", "credential", "secret", "token"]
        .iter()
        .any(|word| normalized.contains(word))
}

fn stmt_targets(stmt: &Stmt) -> impl Iterator<Item = &Expr> {
    match stmt {
        Stmt::Assign(s) => s.targets.iter().collect::<Vec<&Expr>>().into_iter(),
        Stmt::AnnAssign(s) => vec![&*s.target as &Expr].into_iter(),
        _ => Vec::new().into_iter(),
    }
}

// ---------------------------------------------------------------------------
// python:S125 — commented-out code.
// ---------------------------------------------------------------------------

fn check_commented_code(parsed: &Parsed<ModModule>, index: &LineIndex, source: &str) -> Vec<Issue> {
    let mut issues = Vec::new();
    for token in comment_tokens(parsed) {
        if source[token.range()].lines().any(line_looks_like_code) {
            issues.push(Issue {
                rule_key: "python:S125".to_string(),
                message: "Remove this commented-out code.".to_string(),
                range: to_range(token.range(), index, source),
            });
        }
    }
    issues
}

fn line_looks_like_code(line: &str) -> bool {
    const STATEMENT_STARTERS: [&str; 7] =
        ["import", "from", "def", "class", "return", "raise", "del"];
    if line.starts_with("#!") {
        // Shebang: never commented-out code.
        return false;
    }
    let stripped = line.trim_start_matches('#').trim();
    if stripped.is_empty() {
        return false;
    }
    let words: Vec<&str> = stripped
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .filter(|word| !word.is_empty())
        .collect();
    if words
        .first()
        .is_some_and(|word| STATEMENT_STARTERS.contains(word))
    {
        return true;
    }
    let operators = stripped
        .chars()
        .filter(|ch| "()[]{}=:.<>+-*/%|&^~,".contains(*ch))
        .count();
    let keywords = words.iter().filter(|word| is_keyword(word)).count();
    (keywords >= 1 && operators >= 2) || operators >= 3
}

// ---------------------------------------------------------------------------
// Python 2 relics and token-level operator confusion.
// ---------------------------------------------------------------------------

/// python:BackticksUsage — backtick `repr()` quoting.
fn check_py2_backticks(parsed: &Parsed<ModModule>, index: &LineIndex, source: &str) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (base, segment) in unmasked_segments(parsed, source) {
        for (offset, ch) in segment.char_indices() {
            if ch == '`' {
                let at = TextSize::from(to_u32(base + offset));
                issues.push(Issue {
                    rule_key: "python:BackticksUsage".to_string(),
                    message: "Replace the backtick quoting with a call to repr().".to_string(),
                    range: to_range(TextRange::new(at, at + TextSize::new(1)), index, source),
                });
            }
        }
    }
    issues
}

/// python:InequalityUsage — the Python 2 `<>` operator.
fn check_py2_inequality(parsed: &Parsed<ModModule>, index: &LineIndex, source: &str) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (base, segment) in unmasked_segments(parsed, source) {
        for (offset, pair) in segment.as_bytes().windows(2).enumerate() {
            if pair == [b'<', b'>'] {
                let at = TextSize::from(to_u32(base + offset));
                issues.push(Issue {
                    rule_key: "python:InequalityUsage".to_string(),
                    message: "Replace the '<>' operator with '!='.".to_string(),
                    range: to_range(TextRange::new(at, at + TextSize::new(2)), index, source),
                });
            }
        }
    }
    issues
}

/// python:LongIntegerWithLowercaseSuffixUsage — `123l` Python 2 long literal.
fn check_lowercase_long_suffix(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let significant = significant_tokens(parsed);
    significant
        .windows(2)
        .filter(|pair| {
            matches!(
                pair[0].kind(),
                TokenKind::Int | TokenKind::Float | TokenKind::Complex
            ) && pair[1].kind() == TokenKind::Name
                && pair[1].range().start() == pair[0].range().end()
                && &source[pair[1].range()] == "l"
        })
        .map(|pair| Issue {
            rule_key: "python:LongIntegerWithLowercaseSuffixUsage".to_string(),
            message: "Remove this lowercase 'l' suffix; it is a Python 2 long literal.".to_string(),
            range: to_range(
                TextRange::new(pair[0].range().start(), pair[1].range().end()),
                index,
                source,
            ),
        })
        .collect()
}

/// python:PreIncrementDecrement — `++x` / `--x` parsed as double unary ops.
fn check_pre_increment_decrement(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let significant = significant_tokens(parsed);
    let mut issues = Vec::new();
    for index_in_list in 1..significant.len().saturating_sub(1) {
        let current = significant[index_in_list];
        let next = significant[index_in_list + 1];
        let previous = significant[index_in_list - 1];
        let doubled = (current.kind() == TokenKind::Plus && next.kind() == TokenKind::Plus)
            || (current.kind() == TokenKind::Minus && next.kind() == TokenKind::Minus);
        if doubled
            && next.range().start() == current.range().end()
            && !ends_operand(previous, source)
        {
            issues.push(Issue {
                rule_key: "python:PreIncrementDecrement".to_string(),
                message:
                    "Python interprets this as two unary operations; '++' and '--' do not exist."
                        .to_string(),
                range: to_range(
                    TextRange::new(current.range().start(), next.range().end()),
                    index,
                    source,
                ),
            });
        }
    }
    issues
}

/// Whether a token can end an operand, which would turn an adjacent
/// same-sign pair into binary addition instead of a prefix operator.
fn ends_operand(token: &ruff_python_ast::token::Token, source: &str) -> bool {
    match token.kind() {
        TokenKind::Name => !is_keyword(&source[token.range()]),
        TokenKind::Int
        | TokenKind::Float
        | TokenKind::Complex
        | TokenKind::String
        | TokenKind::Rpar
        | TokenKind::Rsqb => true,
        _ => false,
    }
}

/// python:S2757 — `x =+ 1` / `x =- 1` non-existent operators.
fn check_assign_plus_minus(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let significant = significant_tokens(parsed);
    significant
        .windows(2)
        .filter(|pair| {
            pair[0].kind() == TokenKind::Equal
                && matches!(pair[1].kind(), TokenKind::Plus | TokenKind::Minus)
                && pair[1].range().start() == pair[0].range().end()
        })
        .map(|pair| {
            let sign = if pair[1].kind() == TokenKind::Plus {
                '+'
            } else {
                '-'
            };
            Issue {
                rule_key: "python:S2757".to_string(),
                message: format!("Was the '{sign}=' operator meant instead of '={sign}'?"),
                range: to_range(
                    TextRange::new(pair[0].range().start(), pair[1].range().end()),
                    index,
                    source,
                ),
            }
        })
        .collect()
}

/// python:S1717 — invalid escape sequences in non-raw string literals.
fn check_invalid_string_escapes(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        if let Expr::StringLiteral(literal) = expr
            && !matches!(
                literal.value.first_literal_flags().prefix(),
                ruff_python_ast::str_prefix::StringLiteralPrefix::Raw { .. }
            )
        {
            let raw = &source[literal.range()];
            for offset in invalid_escape_offsets(raw) {
                let at = literal.range().start() + TextSize::from(to_u32(offset));
                let escaped = raw[offset + 1..].chars().next().unwrap_or('?');
                issues.push(Issue {
                    rule_key: "python:S1717".to_string(),
                    message: format!("Escape this backslash or make the string raw; '\\{escaped}' is not a recognized escape sequence."),
                    range: to_range(TextRange::new(at, at + TextSize::new(1)), index, source),
                });
            }
        }
    });
    issues
}

/// Byte offsets of backslashes introducing unrecognized escapes.
fn invalid_escape_offsets(raw: &str) -> Vec<usize> {
    let bytes = raw.as_bytes();
    let Some(quote_at) = bytes.iter().position(|&byte| byte == b'\'' || byte == b'"') else {
        return Vec::new();
    };
    let quote = bytes[quote_at];
    let triple = bytes[quote_at..].starts_with(&[quote, quote, quote]);
    let mut offsets = Vec::new();
    let mut i = quote_at + if triple { 3 } else { 1 };
    let end = raw.len().saturating_sub(if triple { 3 } else { 1 });
    while i < end {
        if bytes[i] == b'\\' {
            match bytes.get(i + 1) {
                None => break,
                Some(b'\n' | b'\r') => i += 2,
                Some(&next) if is_valid_escape_byte(next) => i += 2,
                Some(_) => {
                    offsets.push(i);
                    i += 2;
                }
            }
        } else {
            i += 1;
        }
    }
    offsets
}

fn is_valid_escape_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'\\'
            | b'\''
            | b'"'
            | b'a'
            | b'b'
            | b'f'
            | b'n'
            | b'r'
            | b't'
            | b'v'
            | b'x'
            | b'N'
            | b'u'
            | b'U'
    ) || byte.is_ascii_digit()
}

/// python:S1721 — parentheses right after `assert`, `del`, `return`, `yield`.
/// `print` is deliberately excluded: in Python 3 it is a regular function,
/// so `print(x)` is an ordinary call, not a relic.
fn check_keyword_parentheses(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    const PAREN_KEYWORDS: [&str; 4] = ["assert", "del", "return", "yield"];
    let significant = significant_tokens(parsed);
    significant
        .windows(2)
        .filter(|pair| {
            pair[0].kind() == TokenKind::Name
                && PAREN_KEYWORDS.contains(&&source[pair[0].range()])
                && pair[1].kind() == TokenKind::Lpar
                && pair[1].range().start() == pair[0].range().end()
        })
        .map(|pair| {
            let keyword = &source[pair[0].range()];
            Issue {
                rule_key: "python:S1721".to_string(),
                message: format!("Remove the parentheses after '{keyword}'."),
                range: to_range(pair[0].range(), index, source),
            }
        })
        .collect()
}

/// python:S5799 — implicit concatenation mixing str and bytes literals.
fn check_mixed_string_concatenation(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let is_string = |kind: TokenKind| kind == TokenKind::String;
    let significant = significant_tokens(parsed);
    let mut issues = Vec::new();
    for pair in significant.windows(2) {
        if is_string(pair[0].kind())
            && is_string(pair[1].kind())
            && is_bytes_literal(&source[pair[0].range()])
                != is_bytes_literal(&source[pair[1].range()])
        {
            issues.push(Issue {
                rule_key: "python:S5799".to_string(),
                message: "Implicitly concatenating str and bytes literals fails at runtime; merge them explicitly.".to_string(),
                range: to_range(pair[1].range(), index, source),
            });
        }
    }
    issues
}

fn is_bytes_literal(raw: &str) -> bool {
    let prefix = raw
        .split(['"', '\''])
        .next()
        .unwrap_or_default()
        .to_lowercase();
    prefix.contains('b')
}

// ---------------------------------------------------------------------------
// Tier-A battery entries #48–#110 (python:S2772 … python:S7512).
//
// One private check per catalog entry, wired through `check_tier_a_battery`.
// Detection follows the batch spec: single-file AST/token/text heuristics
// with deliberately conservative predicates.
// ---------------------------------------------------------------------------

/// Builds an issue anchored at `range`.
fn issue_at(
    rule_key: &str,
    message: &str,
    range: TextRange,
    index: &LineIndex,
    source: &str,
) -> Issue {
    Issue {
        rule_key: rule_key.to_string(),
        message: message.to_string(),
        range: to_range(range, index, source),
    }
}

/// Whitespace-normalized source text of `expr` (dedent-insensitive equality).
fn expr_normalized_text(expr: &Expr, source: &str) -> String {
    source[expr.range()]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn exprs_textually_equal(left: &Expr, right: &Expr, source: &str) -> bool {
    expr_normalized_text(left, source) == expr_normalized_text(right, source)
}

fn ranges_textually_equal(left: TextRange, right: TextRange, source: &str) -> bool {
    let normalize = |range: TextRange| -> String {
        source[range]
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    };
    normalize(left) == normalize(right)
}

/// Span covering a whole non-empty suite.
fn suite_span(suite: &[Stmt]) -> TextRange {
    TextRange::new(
        suite.first().expect("non-empty").range().start(),
        suite.last().expect("non-empty").range().end(),
    )
}

/// Callee name of a call shaped `name(...)` or `value.name(...)`.
fn called_name(func: &Expr) -> Option<&str> {
    match func {
        Expr::Name(name) => Some(name.id.as_str()),
        Expr::Attribute(attribute) => Some(attribute.attr.as_str()),
        _ => None,
    }
}

fn is_call_to(expr: &Expr, name: &str) -> bool {
    matches!(expr, Expr::Call(call) if called_name(&call.func) == Some(name))
}

/// Positional parameters (`posonlyargs` followed by regular `args`).
fn positional_parameters(
    parameters: &ruff_python_ast::Parameters,
) -> Vec<&ruff_python_ast::Parameter> {
    parameters
        .posonlyargs
        .iter()
        .chain(&parameters.args)
        .map(|with_default| &with_default.parameter)
        .collect()
}

fn is_none_literal(expr: &Expr) -> bool {
    matches!(expr, Expr::NoneLiteral(_))
}

fn is_zero_literal(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::NumberLiteral(number)
            if matches!(&number.value, ruff_python_ast::Number::Int(value) if value.as_i64() == Some(0))
    )
}

fn collect_target_names(target: &Expr, names: &mut Vec<String>) {
    match target {
        Expr::Name(name) => names.push(name.id.to_string()),
        Expr::Tuple(tuple) => {
            for element in &tuple.elts {
                collect_target_names(element, names);
            }
        }
        Expr::List(list) => {
            for element in &list.elts {
                collect_target_names(element, names);
            }
        }
        Expr::Starred(starred) => collect_target_names(&starred.value, names),
        _ => {}
    }
}

/// Whether any `break` lexically bound to a loop over `suite` exists. Breaks
/// inside nested loop bodies belong to the inner loop and do not count.
fn suite_can_break(suite: &[Stmt]) -> bool {
    suite.iter().any(|stmt| match stmt {
        Stmt::Break(_) => true,
        Stmt::For(inner) => suite_can_break(&inner.orelse),
        Stmt::While(inner) => suite_can_break(&inner.orelse),
        Stmt::FunctionDef(_) | Stmt::ClassDef(_) => false,
        _ => child_bodies(stmt).iter().any(|body| suite_can_break(body)),
    })
}
fn check_nested_conditional_expressions(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        for expr in stmt_exprs(stmt) {
            visit_ifexp_branches(expr, false, &mut issues, index, source);
        }
    });
    issues
}

fn visit_ifexp_branches(
    expr: &Expr,
    in_branch: bool,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    match expr {
        Expr::If(nested) => {
            if in_branch {
                issues.push(issue_at(
                    "python:S3358",
                    "Refactor this conditional expression nested inside another into a statement.",
                    nested.range(),
                    index,
                    source,
                ));
            }
            visit_ifexp_branches(&nested.test, false, issues, index, source);
            visit_ifexp_branches(&nested.body, true, issues, index, source);
            visit_ifexp_branches(&nested.orelse, true, issues, index, source);
        }
        _ => {
            for child in child_exprs(expr) {
                visit_ifexp_branches(child, in_branch, issues, index, source);
            }
        }
    }
}

/// Whether `expr`'s subtree loads any of `names`.
fn loads_any_name(expr: &Expr, names: &[String]) -> bool {
    let mut found = false;
    for_each_expr(expr, &mut |node| {
        if let Expr::Name(name) = node
            && matches!(name.ctx, ruff_python_ast::ExprContext::Load)
        {
            found |= names.iter().any(|candidate| candidate == name.id.as_str());
        }
    });
    found
}

/// Whether `expr` contains a floating-point literal anywhere in its subtree.
fn contains_float_literal(expr: &Expr) -> bool {
    let mut found = false;
    for_each_expr(expr, &mut |node| {
        found |= matches!(
            node,
            Expr::NumberLiteral(number) if matches!(number.value, ruff_python_ast::Number::Float(_))
        );
    });
    found
}

/// Canonical grouping text for constant-foldable literal keys/elements.
fn constant_literal_text(expr: &Expr) -> Option<String> {
    match expr {
        Expr::StringLiteral(literal) => Some(format!("s:{}", string_value_text(&literal.value))),
        Expr::BytesLiteral(literal) => {
            let bytes: Vec<u8> = literal
                .value
                .iter()
                .flat_map(|part| part.value.iter())
                .copied()
                .collect();
            Some(format!("b:{bytes:?}"))
        }
        Expr::NumberLiteral(literal) => Some(match &literal.value {
            ruff_python_ast::Number::Int(value) => match value.as_i64() {
                Some(small) => format!("i:{small}"),
                None => "i:large".to_string(),
            },
            ruff_python_ast::Number::Float(value) => format!("f:{value:?}"),
            ruff_python_ast::Number::Complex { real, imag } => format!("c:{real:?}{imag:?}"),
        }),
        Expr::BooleanLiteral(literal) => Some(format!("z:{}", literal.value)),
        Expr::NoneLiteral(_) => Some("n:".to_string()),
        Expr::Tuple(tuple) => {
            let parts: Option<Vec<String>> = tuple.elts.iter().map(constant_literal_text).collect();
            parts.map(|parts| format!("t:({})", parts.join(",")))
        }
        Expr::UnaryOp(unary) if unary.op == ruff_python_ast::UnaryOp::USub => {
            constant_literal_text(&unary.operand).map(|text| format!("-{text}"))
        }
        _ => None,
    }
}

/// Like [`for_each_stmt`] but does not descend into nested function or class
/// scopes.
fn for_each_stmt_in_scope(stmts: &[Stmt], visit: &mut impl FnMut(&Stmt)) {
    for stmt in stmts {
        visit(stmt);
        if matches!(stmt, Stmt::FunctionDef(_) | Stmt::ClassDef(_)) {
            continue;
        }
        for body in child_bodies(stmt) {
            for_each_stmt_in_scope(body, visit);
        }
    }
}

fn has_decorator(function: &ruff_python_ast::StmtFunctionDef, decorator_name: &str) -> bool {
    function
        .decorator_list
        .iter()
        .any(|decorator| match &decorator.expression {
            Expr::Name(name) => name.id.as_str() == decorator_name,
            Expr::Attribute(attribute) => attribute.attr.as_str() == decorator_name,
            _ => false,
        })
}

// --- python:S2772 — needless `pass` ----------------------------------------

#[derive(Clone, Copy)]
enum SuiteOwner {
    Module,
    Class,
    Other,
}

fn check_needless_pass(parsed: &Parsed<ModModule>, index: &LineIndex, source: &str) -> Vec<Issue> {
    let mut issues = Vec::new();
    visit_suites_for_pass(
        parsed.syntax().body.as_slice(),
        SuiteOwner::Module,
        &mut issues,
        index,
        source,
    );
    issues
}

fn visit_suites_for_pass(
    suite: &[Stmt],
    owner: SuiteOwner,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    for (position, stmt) in suite.iter().enumerate() {
        if matches!(stmt, Stmt::Pass(_))
            && suite.len() > 1
            && !(matches!(owner, SuiteOwner::Class) && position == 0)
        {
            issues.push(issue_at(
                "python:S2772",
                "Remove this unnecessary 'pass'.",
                stmt.range(),
                index,
                source,
            ));
        }
        let nested = if matches!(stmt, Stmt::ClassDef(_)) {
            SuiteOwner::Class
        } else {
            SuiteOwner::Other
        };
        for body in child_bodies(stmt) {
            visit_suites_for_pass(body, nested, issues, index, source);
        }
    }
}

// --- python:S2823 — `__all__` must contain only strings ---------------------

fn is_dunder_all_target(expr: &Expr) -> bool {
    matches!(expr, Expr::Name(name) if name.id.as_str() == "__all__")
}

fn check_dunder_all_strings(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in parsed.syntax().body.as_slice() {
        let assigned: Option<&Expr> = match stmt {
            Stmt::Assign(assign) => assign
                .targets
                .iter()
                .any(is_dunder_all_target)
                .then(|| assign.value.as_ref()),
            Stmt::AugAssign(assign) => {
                is_dunder_all_target(&assign.target).then(|| assign.value.as_ref())
            }
            _ => None,
        };
        let elements = match assigned {
            Some(Expr::List(list)) => &list.elts,
            Some(Expr::Set(set)) => &set.elts,
            Some(Expr::Tuple(tuple)) => &tuple.elts,
            _ => continue,
        };
        for element in elements {
            if !matches!(element, Expr::StringLiteral(_)) {
                issues.push(issue_at(
                    "python:S2823",
                    "Only string literals are allowed in '__all__'.",
                    element.range(),
                    index,
                    source,
                ));
            }
        }
    }
    issues
}

// --- python:S2836 — loop `else` without `break` -----------------------------

fn check_loop_else_without_break(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let (body, orelse) = match stmt {
            Stmt::For(loop_stmt) => (&loop_stmt.body, &loop_stmt.orelse),
            Stmt::While(loop_stmt) => (&loop_stmt.body, &loop_stmt.orelse),
            _ => return,
        };
        if orelse.is_empty() || suite_can_break(body) {
            return;
        }
        issues.push(issue_at(
            "python:S2836",
            "This 'else' only runs when the loop finishes without 'break'; remove it or add a 'break'.",
            suite_span(orelse),
            index,
            source,
        ));
    });
    issues
}

// --- python:S3626 — redundant jump statements --------------------------------

fn check_redundant_jump_statements(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| match stmt {
        Stmt::FunctionDef(function) => {
            if let Some(Stmt::Return(last)) = function.body.last()
                && last.value.as_deref().is_none_or(is_none_literal)
            {
                issues.push(issue_at(
                    "python:S3626",
                    "Remove this redundant jump statement.",
                    last.range(),
                    index,
                    source,
                ));
            }
        }
        Stmt::For(for_stmt) => {
            flag_trailing_continue(&for_stmt.body, &mut issues, index, source);
        }
        Stmt::While(while_stmt) => {
            flag_trailing_continue(&while_stmt.body, &mut issues, index, source);
        }
        Stmt::Match(match_stmt) => {
            for case in &match_stmt.cases {
                if let Some(Stmt::Break(last)) = case.body.last() {
                    issues.push(issue_at(
                        "python:S3626",
                        "Remove this redundant jump statement.",
                        last.range(),
                        index,
                        source,
                    ));
                }
            }
        }
        _ => {}
    });
    issues
}

fn flag_trailing_continue(body: &[Stmt], issues: &mut Vec<Issue>, index: &LineIndex, source: &str) {
    if let Some(Stmt::Continue(last)) = body.last() {
        issues.push(issue_at(
            "python:S3626",
            "Remove this redundant jump statement.",
            last.range(),
            index,
            source,
        ));
    }
}

// --- python:S3923 — identical `if`/`else` branches ---------------------------

fn check_identical_if_else_branches(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::If(if_stmt) = stmt else { return };
        let [clause] = &if_stmt.elif_else_clauses[..] else {
            return;
        };
        if clause.test.is_some()
            || !ranges_textually_equal(suite_span(&if_stmt.body), suite_span(&clause.body), source)
        {
            return;
        }
        issues.push(issue_at(
            "python:S3923",
            "Either merge this branch with the identical one or change one of the implementations.",
            if_stmt.range(),
            index,
            source,
        ));
    });
    issues
}

// --- python:S3981 — meaningless collection-size comparisons ------------------

fn check_meaningless_size_comparisons(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Expr::Compare(compare) = expr else { return };
        let meaningless = compare
            .ops
            .iter()
            .zip(&compare.comparators)
            .any(|(op, comparator)| {
                len_zero_verdict(&compare.left, comparator, *op)
                    || len_zero_verdict_swapped(&compare.left, comparator, *op)
            });
        if meaningless {
            issues.push(issue_at(
                "python:S3981",
                "Review this meaningless collection-size comparison.",
                compare.range(),
                index,
                source,
            ));
        }
    });
    issues
}

fn len_zero_verdict(left: &Expr, comparator: &Expr, op: ruff_python_ast::CmpOp) -> bool {
    is_len_call(left)
        && is_zero_literal(comparator)
        && matches!(
            op,
            ruff_python_ast::CmpOp::GtE | ruff_python_ast::CmpOp::Lt | ruff_python_ast::CmpOp::LtE
        )
}

fn len_zero_verdict_swapped(left: &Expr, comparator: &Expr, op: ruff_python_ast::CmpOp) -> bool {
    is_len_call(comparator)
        && is_zero_literal(left)
        && matches!(
            op,
            ruff_python_ast::CmpOp::LtE | ruff_python_ast::CmpOp::Gt | ruff_python_ast::CmpOp::GtE
        )
}

fn is_len_call(expr: &Expr) -> bool {
    matches!(expr, Expr::Call(call) if called_name(&call.func) == Some("len") && call.arguments.args.len() == 1)
}

// --- python:S1763 — unreachable code -----------------------------------------

fn check_unreachable_code(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let scan = |suite: &[Stmt], issues: &mut Vec<Issue>| {
        for (position, stmt) in suite.iter().enumerate() {
            if is_jump_terminator(stmt) {
                for follower in &suite[position + 1..] {
                    issues.push(issue_at(
                        "python:S1763",
                        "This code is unreachable.",
                        follower.range(),
                        index,
                        source,
                    ));
                }
            }
        }
    };
    scan(parsed.syntax().body.as_slice(), &mut issues);
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        for body in child_bodies(stmt) {
            scan(body, &mut issues);
        }
    });
    issues
}

fn is_jump_terminator(stmt: &Stmt) -> bool {
    matches!(
        stmt,
        Stmt::Return(_) | Stmt::Raise(_) | Stmt::Break(_) | Stmt::Continue(_)
    )
}

// --- python:S1764 — identical operands ---------------------------------------

fn check_identical_operands(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| match expr {
        Expr::BinOp(binary) => {
            if exprs_textually_equal(&binary.left, &binary.right, source)
                && !excluded_identical_pair(&binary.left, &binary.right)
            {
                issues.push(issue_at(
                    "python:S1764",
                    "Review this operation; its operands are identical.",
                    binary.range(),
                    index,
                    source,
                ));
            }
        }
        Expr::Compare(compare) => {
            for comparator in &compare.comparators {
                if exprs_textually_equal(&compare.left, comparator, source)
                    && !excluded_identical_pair(&compare.left, comparator)
                {
                    issues.push(issue_at(
                        "python:S1764",
                        "Review this operation; its operands are identical.",
                        compare.range(),
                        index,
                        source,
                    ));
                    break;
                }
            }
        }
        _ => {}
    });
    issues
}

/// RSPEC exempts trivially true identities over the `0`/`1` literals.
fn excluded_identical_pair(left: &Expr, right: &Expr) -> bool {
    is_small_int_literal(left) && is_small_int_literal(right)
}

fn is_small_int_literal(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::NumberLiteral(number)
            if matches!(&number.value, ruff_python_ast::Number::Int(value) if matches!(value.as_u8(), Some(0 | 1)))
    )
}

// --- python:S1862 — identical conditions in an if/elif chain -----------------

fn check_duplicate_conditions(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::If(if_stmt) = stmt else { return };
        let mut previous: Vec<&Expr> = vec![&if_stmt.test];
        for clause in &if_stmt.elif_else_clauses {
            let Some(test) = clause.test.as_ref() else {
                break;
            };
            if previous
                .iter()
                .any(|earlier| exprs_textually_equal(earlier, test, source))
            {
                issues.push(issue_at(
                    "python:S1862",
                    "This condition duplicates an earlier one; this branch can never run.",
                    test.range(),
                    index,
                    source,
                ));
            }
            previous.push(test);
        }
    });
    issues
}

// --- python:S1871 — duplicate conditional branches ---------------------------

fn check_duplicate_branches(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| match stmt {
        Stmt::If(if_stmt) => {
            let mut branches: Vec<&[Stmt]> = vec![&if_stmt.body];
            branches.extend(
                if_stmt
                    .elif_else_clauses
                    .iter()
                    .map(|clause| clause.body.as_slice()),
            );
            flag_duplicate_branches(&branches, "python:S1871", &mut issues, index, source);
        }
        Stmt::Try(try_stmt) => {
            let handlers: Vec<&[Stmt]> = try_stmt
                .handlers
                .iter()
                .map(|handler| match handler {
                    ExceptHandler::ExceptHandler(inner) => inner.body.as_slice(),
                })
                .collect();
            flag_duplicate_branches(&handlers, "python:S1871", &mut issues, index, source);
        }
        _ => {}
    });
    issues
}

fn flag_duplicate_branches(
    branches: &[&[Stmt]],
    rule_key: &str,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    for (later_index, later) in branches.iter().enumerate() {
        for earlier in &branches[..later_index] {
            if ranges_textually_equal(suite_span(later), suite_span(earlier), source) {
                issues.push(issue_at(
                    rule_key,
                    "This branch duplicates an earlier one; merge them or change one implementation.",
                    suite_span(later),
                    index,
                    source,
                ));
                break;
            }
        }
    }
}

// --- python:S1940 — inverted boolean checks ----------------------------------

fn check_inverted_boolean_checks(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        if let Expr::UnaryOp(unary) = expr
            && unary.op == ruff_python_ast::UnaryOp::Not
            && matches!(unary.operand.as_ref(), Expr::Compare(_))
        {
            issues.push(issue_at(
                "python:S1940",
                "Replace this negated comparison with the inverted operator.",
                unary.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- python:S1656 — self-assignment ------------------------------------------

fn check_self_assignment(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| match stmt {
        Stmt::Assign(assign) => {
            if assign.targets.iter().any(|target| {
                is_assignable_shape(target) && exprs_textually_equal(target, &assign.value, source)
            }) {
                issues.push(issue_at(
                    "python:S1656",
                    "Remove this self-assignment.",
                    assign.range(),
                    index,
                    source,
                ));
            }
        }
        Stmt::AnnAssign(annotated) => {
            if let Some(value) = annotated.value.as_deref()
                && is_assignable_shape(&annotated.target)
                && exprs_textually_equal(&annotated.target, value, source)
            {
                issues.push(issue_at(
                    "python:S1656",
                    "Remove this self-assignment.",
                    annotated.range(),
                    index,
                    source,
                ));
            }
        }
        _ => {}
    });
    issues
}

fn is_assignable_shape(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Name(_) | Expr::Attribute(_) | Expr::Subscript(_)
    )
}

// --- python:S2208 — wildcard imports -----------------------------------------

fn check_wildcard_imports(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::ImportFrom(import) = stmt
            && import.names.iter().any(|alias| alias.name.as_str() == "*")
        {
            issues.push(issue_at(
                "python:S2208",
                "Name the symbols to import explicitly instead of importing '*'.",
                import.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- python:S2761 — doubled prefix operators ---------------------------------

fn check_doubled_prefix_operators(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        if let Expr::UnaryOp(unary) = expr
            && let Expr::UnaryOp(inner) = unary.operand.as_ref()
            && unary.op == inner.op
            && matches!(
                unary.op,
                ruff_python_ast::UnaryOp::Not | ruff_python_ast::UnaryOp::Invert
            )
        {
            issues.push(issue_at(
                "python:S2761",
                "Remove this doubled prefix operator.",
                unary.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- python:S5685 — confusing walrus operator placement ----------------------

fn check_confusing_walrus_placement(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| match expr {
        Expr::ListComp(comp) => flag_comprehension_walrus(&comp.elt, &mut issues, index, source),
        Expr::SetComp(comp) => flag_comprehension_walrus(&comp.elt, &mut issues, index, source),
        Expr::Generator(comp) => flag_comprehension_walrus(&comp.elt, &mut issues, index, source),
        Expr::DictComp(comp) => {
            if let Some(key) = &comp.key {
                flag_comprehension_walrus(key, &mut issues, index, source);
            }
            flag_comprehension_walrus(&comp.value, &mut issues, index, source);
        }
        Expr::Compare(compare) => {
            let chained = compare.ops.len() > 1;
            if chained {
                if matches!(compare.left.as_ref(), Expr::Named(_)) {
                    issues.push(issue_at(
                        "python:S5685",
                        "Move this walrus operator to a clearer location.",
                        compare.left.range(),
                        index,
                        source,
                    ));
                }
                for comparator in &compare.comparators {
                    if matches!(comparator, Expr::Named(_)) {
                        issues.push(issue_at(
                            "python:S5685",
                            "Move this walrus operator to a clearer location.",
                            comparator.range(),
                            index,
                            source,
                        ));
                    }
                }
            }
        }
        _ => {}
    });
    issues
}

fn flag_comprehension_walrus(
    element: &Expr,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    if matches!(element, Expr::Named(_)) {
        issues.push(issue_at(
            "python:S5685",
            "Move this walrus operator to a clearer location.",
            element.range(),
            index,
            source,
        ));
    }
}

// --- python:S5727 — constant comparison to None -------------------------------

fn check_constant_none_comparisons(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Expr::Compare(compare) = expr else { return };
        let mut sides: Vec<&Expr> = vec![&compare.left];
        sides.extend(&compare.comparators);
        let constant_involved = sides.iter().any(|side| {
            is_none_literal(side)
                && sides.iter().any(|other| {
                    !std::ptr::eq(*side, *other) && constant_literal_text(other).is_some()
                })
        });
        if constant_involved {
            issues.push(issue_at(
                "python:S5727",
                "Review this comparison; it involves only constants and 'None'.",
                compare.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- python:S5796 — identity check on freshly created objects ----------------

fn check_fresh_object_identity_checks(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Expr::Compare(compare) = expr else { return };
        let identity = compare.ops.iter().any(|op| {
            matches!(
                op,
                ruff_python_ast::CmpOp::Is | ruff_python_ast::CmpOp::IsNot
            )
        });
        if !identity {
            return;
        }
        let mut sides: Vec<&Expr> = vec![&compare.left];
        sides.extend(&compare.comparators);
        if sides.iter().any(|side| is_freshly_created(side)) {
            issues.push(issue_at(
                "python:S5796",
                "Do not test freshly created objects for identity; compare values with '=='.",
                compare.range(),
                index,
                source,
            ));
        }
    });
    issues
}

fn is_freshly_created(expr: &Expr) -> bool {
    match expr {
        Expr::List(_)
        | Expr::Set(_)
        | Expr::Tuple(_)
        | Expr::Dict(_)
        | Expr::ListComp(_)
        | Expr::SetComp(_)
        | Expr::DictComp(_)
        | Expr::Generator(_) => true,
        Expr::Call(call) => matches!(
            called_name(&call.func),
            Some("list" | "dict" | "set" | "tuple" | "frozenset")
        ),
        _ => false,
    }
}

// --- python:S5905 — assert on a tuple literal ---------------------------------

fn check_tuple_assertions(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::Assert(assert) = stmt
            && let Expr::Tuple(tuple) = assert.test.as_ref()
            && !tuple.elts.is_empty()
        {
            issues.push(issue_at(
                "python:S5905",
                "This assertion always passes because it tests a non-empty tuple.",
                assert.test.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- python:S6660 — `type()` equality instead of isinstance -------------------

fn check_type_equality_comparisons(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Expr::Compare(compare) = expr else { return };
        if !compare.ops.iter().any(|op| {
            matches!(
                op,
                ruff_python_ast::CmpOp::Eq
                    | ruff_python_ast::CmpOp::NotEq
                    | ruff_python_ast::CmpOp::Is
                    | ruff_python_ast::CmpOp::IsNot
            )
        }) {
            return;
        }
        let mut sides: Vec<&Expr> = vec![&compare.left];
        sides.extend(&compare.comparators);
        let flagged = sides.iter().any(|side| {
            is_type_call(side)
                && sides.iter().any(|other| {
                    !std::ptr::eq(*side, *other)
                        && matches!(other, Expr::Name(_) | Expr::Attribute(_))
                })
        });
        if flagged {
            issues.push(issue_at(
                "python:S6660",
                "Use 'isinstance' instead of comparing the result of 'type()' directly.",
                compare.range(),
                index,
                source,
            ));
        }
    });
    issues
}

fn is_type_call(expr: &Expr) -> bool {
    matches!(expr, Expr::Call(call)
        if called_name(&call.func) == Some("type")
            && call.arguments.args.len() == 1
            && call.arguments.keywords.is_empty())
}

// --- python:S6661 — lambda assigned to a variable -----------------------------

fn check_lambda_assignments(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| match stmt {
        Stmt::Assign(assign) => {
            if let Expr::Lambda(lambda) = assign.value.as_ref() {
                issues.push(issue_at(
                    "python:S6661",
                    "Replace this assigned lambda with a 'def' statement.",
                    lambda.range(),
                    index,
                    source,
                ));
            }
        }
        Stmt::AnnAssign(annotated) => {
            if let Some(Expr::Lambda(lambda)) = annotated.value.as_deref() {
                issues.push(issue_at(
                    "python:S6661",
                    "Replace this assigned lambda with a 'def' statement.",
                    lambda.range(),
                    index,
                    source,
                ));
            }
        }
        _ => {}
    });
    issues
}

// --- python:S6659 — startswith/endswith over slicing --------------------------

fn check_boundary_slice_comparisons(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Expr::Compare(compare) = expr else { return };
        if !compare.ops.iter().any(|op| {
            matches!(
                op,
                ruff_python_ast::CmpOp::Eq
                    | ruff_python_ast::CmpOp::NotEq
                    | ruff_python_ast::CmpOp::Is
                    | ruff_python_ast::CmpOp::IsNot
            )
        }) {
            return;
        }
        let mut sides: Vec<&Expr> = vec![&compare.left];
        sides.extend(&compare.comparators);
        let flagged = sides.iter().any(|side| {
            is_boundary_slice(side)
                && sides.iter().any(|other| {
                    !std::ptr::eq(*side, *other) && matches!(other, Expr::StringLiteral(_))
                })
        });
        if flagged {
            issues.push(issue_at(
                "python:S6659",
                "Use 'startswith' or 'endswith' for this prefix or suffix comparison.",
                compare.range(),
                index,
                source,
            ));
        }
    });
    issues
}

fn is_boundary_slice(expr: &Expr) -> bool {
    let Expr::Subscript(subscript) = expr else {
        return false;
    };
    let Expr::Slice(slice) = subscript.slice.as_ref() else {
        return false;
    };
    if slice.step.is_some() {
        return false;
    }
    match (&slice.lower, &slice.upper) {
        (None, Some(_)) => true,
        (Some(bound), None) => {
            matches!(bound.as_ref(), Expr::UnaryOp(unary)
                if unary.op == ruff_python_ast::UnaryOp::USub
                    && matches!(unary.operand.as_ref(), Expr::NumberLiteral(_)))
        }
        _ => false,
    }
}

// --- python:S1244 — float equality testing ------------------------------------

fn check_float_equality_comparisons(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Expr::Compare(compare) = expr else { return };
        let equality = compare.ops.iter().any(|op| {
            matches!(
                op,
                ruff_python_ast::CmpOp::Eq | ruff_python_ast::CmpOp::NotEq
            )
        });
        if !equality {
            return;
        }
        let float_involved = contains_float_literal(&compare.left)
            || compare.comparators.iter().any(contains_float_literal);
        if float_involved {
            issues.push(issue_at(
                "python:S1244",
                "Compare floating-point values with a tolerance instead of testing equality exactly.",
                compare.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- python:S905 — statements without effect ----------------------------------

fn check_no_effect_statements(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    visit_suites_for_no_effect(parsed.syntax().body.as_slice(), &mut issues, index, source);
    issues
}

fn visit_suites_for_no_effect(
    suite: &[Stmt],
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    for (position, stmt) in suite.iter().enumerate() {
        if let Stmt::Expr(value) = stmt
            && !(position == 0 && matches!(value.value.as_ref(), Expr::StringLiteral(_)))
            && statement_has_no_effect(&value.value)
        {
            issues.push(issue_at(
                "python:S905",
                "Remove this statement; it has no effect.",
                stmt.range(),
                index,
                source,
            ));
        }
        for body in child_bodies(stmt) {
            visit_suites_for_no_effect(body, issues, index, source);
        }
    }
}

fn statement_has_no_effect(expr: &Expr) -> bool {
    match expr {
        Expr::NoneLiteral(_)
        | Expr::BooleanLiteral(_)
        | Expr::NumberLiteral(_)
        | Expr::StringLiteral(_)
        | Expr::BytesLiteral(_)
        | Expr::EllipsisLiteral(_)
        | Expr::Name(_) => true,
        Expr::Tuple(tuple) => tuple.elts.iter().all(statement_has_no_effect),
        Expr::List(list) => list.elts.iter().all(statement_has_no_effect),
        Expr::Set(set) => set.elts.iter().all(statement_has_no_effect),
        Expr::Dict(dict) => dict.items.iter().all(|item| {
            item.key.as_ref().is_none_or(statement_has_no_effect)
                && statement_has_no_effect(&item.value)
        }),
        Expr::UnaryOp(unary) => statement_has_no_effect(&unary.operand),
        Expr::BinOp(binary) => {
            statement_has_no_effect(&binary.left) && statement_has_no_effect(&binary.right)
        }
        Expr::BoolOp(boolean) => boolean.values.iter().all(statement_has_no_effect),
        Expr::Compare(compare) => {
            statement_has_no_effect(&compare.left)
                && compare.comparators.iter().all(statement_has_no_effect)
        }
        _ => false,
    }
}

// --- python:S2733 — `__exit__` signature --------------------------------------

fn check_exit_signatures(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::FunctionDef(function) = stmt
            && function.name.as_str() == "__exit__"
            && positional_parameters(&function.parameters).len() < 4
        {
            issues.push(issue_at(
                "python:S2733",
                "'__exit__' requires the exc_type, exc_value and traceback parameters.",
                function.name.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- python:S2734 — `__init__` returning a value ------------------------------

fn check_init_return_values(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::FunctionDef(function) = stmt
            && function.name.as_str() == "__init__"
        {
            for_each_stmt_in_scope(&function.body, &mut |inner| {
                if let Stmt::Return(returned) = inner
                    && let Some(value) = returned.value.as_deref()
                    && !is_none_literal(value)
                {
                    issues.push(issue_at(
                        "python:S2734",
                        "Remove this 'return'; '__init__' cannot return a value.",
                        returned.range(),
                        index,
                        source,
                    ));
                }
            });
        }
    });
    issues
}

// --- python:S2737 — except clause that only re-raises -------------------------

fn check_only_reraise_handlers(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::Try(try_stmt) = stmt else { return };
        for handler in &try_stmt.handlers {
            let ExceptHandler::ExceptHandler(inner) = handler;
            let [only] = &inner.body[..] else { continue };
            let Stmt::Raise(raised) = only else { continue };
            let caught = exception_type_names(inner.type_.as_deref());
            let pure_reraise = raised.exc.is_none() && raised.cause.is_none()
                || raised.exc.as_deref().is_some_and(
                    |exc| matches!(exc, Expr::Name(name) if caught.contains(&name.id.to_string())),
                );
            if pure_reraise {
                issues.push(issue_at(
                    "python:S2737",
                    "Remove this 'except' clause or handle the exception; it only re-raises.",
                    handler.range(),
                    index,
                    source,
                ));
            }
        }
    });
    issues
}

/// Names caught by an except type expression (`Name`, attribute tail, or any
/// element of a tuple).
fn exception_type_names(type_expr: Option<&Expr>) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(expr) = type_expr {
        collect_exception_names(expr, &mut names);
    }
    names
}

fn collect_exception_names(expr: &Expr, names: &mut Vec<String>) {
    match expr {
        Expr::Name(name) => names.push(name.id.to_string()),
        Expr::Attribute(attribute) => names.push(attribute.attr.to_string()),
        Expr::Tuple(tuple) => {
            for element in &tuple.elts {
                collect_exception_names(element, names);
            }
        }
        _ => {}
    }
}

// --- python:S5712 — special methods raising NotImplementedError ---------------

const PROTOCOL_DUNDERS: [&str; 34] = [
    "__add__",
    "__sub__",
    "__mul__",
    "__truediv__",
    "__floordiv__",
    "__mod__",
    "__pow__",
    "__lshift__",
    "__rshift__",
    "__and__",
    "__or__",
    "__xor__",
    "__radd__",
    "__rsub__",
    "__rmul__",
    "__rtruediv__",
    "__rfloordiv__",
    "__rmod__",
    "__rpow__",
    "__rlshift__",
    "__rrshift__",
    "__rand__",
    "__ror__",
    "__rxor__",
    "__iadd__",
    "__isub__",
    "__imul__",
    "__eq__",
    "__ne__",
    "__lt__",
    "__le__",
    "__gt__",
    "__ge__",
    "__hash__",
];

fn check_notimplemented_raises(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::FunctionDef(function) = stmt
            && PROTOCOL_DUNDERS.contains(&function.name.as_str())
        {
            for_each_stmt_in_scope(&function.body, &mut |inner| {
                if let Stmt::Raise(raised) = inner
                    && raised
                        .exc
                        .as_deref()
                        .is_some_and(is_notimplemented_error_expr)
                {
                    issues.push(issue_at(
                        "python:S5712",
                        "Return 'NotImplemented' instead of raising 'NotImplementedError'.",
                        raised.range(),
                        index,
                        source,
                    ));
                }
            });
        }
    });
    issues
}

fn is_notimplemented_error_expr(expr: &Expr) -> bool {
    match expr {
        Expr::Name(name) => name.id.as_str() == "NotImplementedError",
        Expr::Call(call) => {
            matches!(call.func.as_ref(), Expr::Name(name) if name.id.as_str() == "NotImplementedError")
        }
        _ => false,
    }
}

// --- python:S5719 — instance/class methods need a positional parameter --------

/// Iterates `(class, function)` for every method directly defined in a class
/// body anywhere in the tree.
fn for_each_method(
    stmts: &[Stmt],
    visit: &mut impl FnMut(&ruff_python_ast::StmtClassDef, &ruff_python_ast::StmtFunctionDef),
) {
    for_each_stmt(stmts, &mut |stmt| {
        if let Stmt::ClassDef(class) = stmt {
            for member in &class.body {
                if let Stmt::FunctionDef(function) = member {
                    visit(class, function);
                }
            }
        }
    });
}

fn check_methods_missing_parameters(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_method(parsed.syntax().body.as_slice(), &mut |_class, function| {
        if !has_decorator(function, "staticmethod")
            && positional_parameters(&function.parameters).is_empty()
        {
            issues.push(issue_at(
                "python:S5719",
                "Add the missing instance or class method parameter ('self' or 'cls').",
                function.name.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- python:S5720 — `self` must be the first instance-method parameter --------

fn check_instance_self_parameters(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_method(parsed.syntax().body.as_slice(), &mut |_class, function| {
        if has_decorator(function, "staticmethod") || has_decorator(function, "classmethod") {
            return;
        }
        if let Some(first) = positional_parameters(&function.parameters).first()
            && first.name.as_str() != "self"
        {
            issues.push(issue_at(
                "python:S5720",
                "Rename this first parameter to 'self'.",
                first.name.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- python:S5722 — special method arity --------------------------------------

const ARITY_ONE_DUNDERS: [&str; 17] = [
    "__str__",
    "__repr__",
    "__len__",
    "__hash__",
    "__bool__",
    "__iter__",
    "__next__",
    "__enter__",
    "__dir__",
    "__index__",
    "__neg__",
    "__pos__",
    "__invert__",
    "__abs__",
    "__int__",
    "__float__",
    "__complex__",
];

const ARITY_TWO_DUNDERS: [&str; 39] = [
    "__add__",
    "__sub__",
    "__mul__",
    "__truediv__",
    "__floordiv__",
    "__mod__",
    "__pow__",
    "__lshift__",
    "__rshift__",
    "__and__",
    "__or__",
    "__xor__",
    "__eq__",
    "__ne__",
    "__lt__",
    "__le__",
    "__gt__",
    "__ge__",
    "__radd__",
    "__rsub__",
    "__rmul__",
    "__rtruediv__",
    "__rfloordiv__",
    "__rmod__",
    "__rpow__",
    "__rlshift__",
    "__rrshift__",
    "__rand__",
    "__ror__",
    "__rxor__",
    "__iadd__",
    "__isub__",
    "__imul__",
    "__contains__",
    "__getitem__",
    "__delitem__",
    "__getattr__",
    "__getattribute__",
    "__delete__",
];

const ARITY_THREE_DUNDERS: [&str; 4] =
    ["__setitem__", "__setattr__", "__delattr__", "__set_name__"];

fn required_special_method_arity(name: &str) -> Option<usize> {
    if ARITY_ONE_DUNDERS.contains(&name) {
        Some(1)
    } else if ARITY_TWO_DUNDERS.contains(&name) {
        Some(2)
    } else if ARITY_THREE_DUNDERS.contains(&name) {
        Some(3)
    } else {
        None
    }
}

fn check_special_method_arities(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::FunctionDef(function) = stmt else {
            return;
        };
        let Some(required) = required_special_method_arity(function.name.as_str()) else {
            return;
        };
        if function.name.as_str() == "__exit__"
            || function.parameters.vararg.is_some()
            || positional_parameters(&function.parameters).len() >= required
        {
            return;
        }
        issues.push(issue_at(
            "python:S5722",
            "Fix this special method signature; it is missing required parameters.",
            function.name.range(),
            index,
            source,
        ));
    });
    issues
}

// --- python:S5724 — property accessor arity -----------------------------------

fn check_property_accessor_arities(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_method(parsed.syntax().body.as_slice(), &mut |_class, function| {
        let required = if has_decorator(function, "property") {
            1
        } else if has_decorator(function, "setter") || has_decorator(function, "deleter") {
            2
        } else {
            return;
        };
        if positional_parameters(&function.parameters).len() == required {
            return;
        }
        issues.push(issue_at(
            "python:S5724",
            "Fix the parameter count of this property accessor.",
            function.name.range(),
            index,
            source,
        ));
    });
    issues
}

// --- python:S5709 — custom exceptions inherit Exception -----------------------

fn looks_like_exception_name(name: &str) -> bool {
    name.ends_with("Error") || name.ends_with("Warning") || name.ends_with("Exception")
}

fn is_builtin_exception_base(expr: &Expr) -> bool {
    let tail = match expr {
        Expr::Name(name) => Some(name.id.as_str()),
        Expr::Attribute(attribute) => Some(attribute.attr.as_str()),
        _ => None,
    };
    matches!(tail, Some(base) if base == "Exception" || base == "BaseException" || looks_like_exception_name(base))
}

fn check_exception_inheritance(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::ClassDef(class) = stmt
            && looks_like_exception_name(class.name.as_str())
            && !class.bases().iter().any(is_builtin_exception_base)
        {
            issues.push(issue_at(
                "python:S5709",
                "Make this exception inherit from a built-in exception class.",
                class.name.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- python:S5714 — boolean expression in except clause -----------------------

fn check_boolean_except_clauses(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::Try(try_stmt) = stmt else { return };
        for handler in &try_stmt.handlers {
            let ExceptHandler::ExceptHandler(inner) = handler;
            let Some(type_expr) = inner.type_.as_deref() else {
                continue;
            };
            let mut boolean = false;
            for_each_expr(type_expr, &mut |node| {
                boolean |= matches!(node, Expr::BoolOp(_) | Expr::If(_));
            });
            if boolean {
                issues.push(issue_at(
                    "python:S5714",
                    "Simplify this except specification; boolean expressions cannot be caught.",
                    type_expr.range(),
                    index,
                    source,
                ));
            }
        }
    });
    issues
}

// --- python:S5704/S5747/S1143/S1716 — raise/jump flow placement ---------------

#[derive(Clone, Copy, PartialEq)]
enum RaiseContext {
    Outside,
    InExcept,
    InFinally,
}

fn check_raise_and_jump_flow(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    scan_flow_statements(
        parsed.syntax().body.as_slice(),
        FlowState {
            context: RaiseContext::Outside,
            finally_depth: 0,
            loop_depth: 0,
        },
        &mut issues,
        index,
        source,
    );
    issues
}

/// Lexical raise/jump binding state carried by the flow walk.
#[derive(Clone, Copy)]
struct FlowState {
    context: RaiseContext,
    finally_depth: u32,
    loop_depth: u32,
}

impl FlowState {
    fn with_loop(self) -> Self {
        Self {
            loop_depth: self.loop_depth + 1,
            ..self
        }
    }

    fn in_finally(self) -> Self {
        Self {
            context: RaiseContext::InFinally,
            finally_depth: self.finally_depth + 1,
            ..self
        }
    }

    fn fresh_scope() -> Self {
        Self {
            context: RaiseContext::Outside,
            finally_depth: 0,
            loop_depth: 0,
        }
    }
}

fn scan_flow_statements(
    suite: &[Stmt],
    state: FlowState,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    for stmt in suite {
        match stmt {
            Stmt::Break(_) | Stmt::Continue(_) => {
                flag_flow_jump(stmt, state, issues, index, source);
            }
            Stmt::Return(_) => {
                if state.finally_depth > 0 {
                    issues.push(issue_at(
                        "python:S1143",
                        "Move this return statement out of 'finally'; it discards the in-flight exception.",
                        stmt.range(),
                        index,
                        source,
                    ));
                }
            }
            Stmt::Raise(raised) => flag_flow_raise(raised, state, issues, index, source),
            _ => scan_flow_nested_bodies(stmt, state, issues, index, source),
        }
    }
}

fn flag_flow_jump(
    stmt: &Stmt,
    state: FlowState,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    if state.finally_depth > 0 {
        issues.push(issue_at(
            "python:S1143",
            "Move this jump statement out of 'finally'; it discards the in-flight exception.",
            stmt.range(),
            index,
            source,
        ));
    } else if state.loop_depth == 0 {
        issues.push(issue_at(
            "python:S1716",
            "Remove this jump statement; no enclosing loop exists.",
            stmt.range(),
            index,
            source,
        ));
    }
}

fn flag_flow_raise(
    raised: &ruff_python_ast::StmtRaise,
    state: FlowState,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    if raised.exc.is_some() || raised.cause.is_some() || state.context == RaiseContext::InExcept {
        return;
    }
    let (key, message) = if state.context == RaiseContext::InFinally {
        (
            "python:S5704",
            "A bare 'raise' inside 'finally' masks the in-flight exception.",
        )
    } else {
        (
            "python:S5747",
            "A bare 'raise' is only allowed in an 'except' clause; raise an explicit exception.",
        )
    };
    issues.push(issue_at(key, message, raised.range(), index, source));
}

fn scan_flow_nested_bodies(
    stmt: &Stmt,
    state: FlowState,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    match stmt {
        Stmt::For(loop_stmt) => {
            scan_flow_statements(&loop_stmt.body, state.with_loop(), issues, index, source);
            scan_flow_statements(&loop_stmt.orelse, state, issues, index, source);
        }
        Stmt::While(loop_stmt) => {
            scan_flow_statements(&loop_stmt.body, state.with_loop(), issues, index, source);
            scan_flow_statements(&loop_stmt.orelse, state, issues, index, source);
        }
        Stmt::Try(try_stmt) => {
            scan_flow_statements(&try_stmt.body, state, issues, index, source);
            for handler in &try_stmt.handlers {
                let ExceptHandler::ExceptHandler(inner) = handler;
                scan_flow_statements(
                    &inner.body,
                    FlowState {
                        context: RaiseContext::InExcept,
                        ..state
                    },
                    issues,
                    index,
                    source,
                );
            }
            scan_flow_statements(&try_stmt.orelse, state, issues, index, source);
            scan_flow_statements(
                &try_stmt.finalbody,
                state.in_finally(),
                issues,
                index,
                source,
            );
        }
        Stmt::With(with_stmt) => {
            scan_flow_statements(&with_stmt.body, state, issues, index, source);
        }
        Stmt::If(if_stmt) => {
            scan_flow_statements(&if_stmt.body, state, issues, index, source);
            for clause in &if_stmt.elif_else_clauses {
                scan_flow_statements(&clause.body, state, issues, index, source);
            }
        }
        Stmt::Match(match_stmt) => {
            for case in &match_stmt.cases {
                scan_flow_statements(&case.body, state, issues, index, source);
            }
        }
        // Jumps bind within the innermost function scope; reset the state.
        Stmt::FunctionDef(function) => {
            scan_flow_statements(
                &function.body,
                FlowState::fresh_scope(),
                issues,
                index,
                source,
            );
        }
        _ => {}
    }
}

// --- python:S5706 — `__exit__` re-raising the provided exception --------------

fn check_exit_reraises_argument(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::FunctionDef(function) = stmt else {
            return;
        };
        if function.name.as_str() != "__exit__" {
            return;
        }
        let arguments: Vec<String> = positional_parameters(&function.parameters)
            .iter()
            .skip(1)
            .map(|parameter| parameter.name.to_string())
            .collect();
        for_each_stmt_in_scope(&function.body, &mut |inner| {
            if let Stmt::Raise(raised) = inner
                && let Some(Expr::Name(name)) = raised.exc.as_deref()
                && arguments.contains(&name.id.to_string())
            {
                issues.push(issue_at(
                    "python:S5706",
                    "Remove this 'raise'; '__exit__' must not re-raise the exception argument.",
                    raised.range(),
                    index,
                    source,
                ));
            }
        });
    });
    issues
}

// --- python:S5754 — SystemExit must be re-raised -------------------------------

fn check_swallowed_system_exit(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::Try(try_stmt) = stmt else { return };
        for handler in &try_stmt.handlers {
            let ExceptHandler::ExceptHandler(inner) = handler;
            let caught = exception_type_names(inner.type_.as_deref());
            if !caught.iter().any(|name| name == "SystemExit") {
                continue;
            }
            let mut re_raised = false;
            for_each_stmt_in_scope(&inner.body, &mut |candidate| {
                re_raised |= matches!(candidate, Stmt::Raise(_));
            });
            if !re_raised {
                issues.push(issue_at(
                    "python:S5754",
                    "Re-raise 'SystemExit'; swallowing it prevents proper termination.",
                    handler.range(),
                    index,
                    source,
                ));
            }
        }
    });
    issues
}

// --- python:S1515 — closures capturing loop variables --------------------------

fn check_closure_captures_loop_variable(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::For(for_stmt) = stmt else { return };
        let mut targets = Vec::new();
        collect_target_names(&for_stmt.target, &mut targets);
        if targets.is_empty() {
            return;
        }
        for_each_stmt_expr(&for_stmt.body, &mut |expr| {
            if let Expr::Lambda(lambda) = expr
                && loads_any_name(&lambda.body, &targets)
            {
                issues.push(issue_at(
                    "python:S1515",
                    "This closure captures a loop variable by reference; bind it with a default argument.",
                    lambda.range(),
                    index,
                    source,
                ));
            }
        });
        for_each_stmt(&for_stmt.body, &mut |nested| {
            if let Stmt::FunctionDef(function) = nested
                && stmts_load_any_name(&function.body, &targets)
            {
                issues.push(issue_at(
                    "python:S1515",
                    "This closure captures a loop variable by reference; bind it with a default argument.",
                    function.name.range(),
                    index,
                    source,
                ));
            }
        });
    });
    issues
}

fn stmts_load_any_name(stmts: &[Stmt], names: &[String]) -> bool {
    let mut found = false;
    for_each_stmt_expr(stmts, &mut |expr| {
        found |= loads_any_name(expr, names);
    });
    found
}

// --- python:S2710 — classmethod first argument naming --------------------------

fn check_classmethod_parameter_names(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_method(parsed.syntax().body.as_slice(), &mut |_class, function| {
        if !has_decorator(function, "classmethod") {
            return;
        }
        if let Some(first) = positional_parameters(&function.parameters).first()
            && !matches!(first.name.as_str(), "cls" | "mcs" | "metacls")
        {
            issues.push(issue_at(
                "python:S2710",
                "Rename this first parameter to 'cls'.",
                first.name.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- python:S2711 — yield/return outside a function ----------------------------

fn check_yield_return_outside_function(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    visit_scopes_for_yields(
        parsed.syntax().body.as_slice(),
        0,
        &mut issues,
        index,
        source,
    );
    issues
}

fn visit_scopes_for_yields(
    suite: &[Stmt],
    function_depth: u32,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    for stmt in suite {
        match stmt {
            Stmt::FunctionDef(function) => {
                visit_scopes_for_yields(&function.body, function_depth + 1, issues, index, source);
            }
            Stmt::ClassDef(class) => {
                visit_scopes_for_yields(&class.body, function_depth, issues, index, source);
            }
            _ => {
                if function_depth == 0 {
                    if matches!(stmt, Stmt::Return(_)) {
                        issues.push(issue_at(
                            "python:S2711",
                            "Remove this 'return'; it appears outside a function.",
                            stmt.range(),
                            index,
                            source,
                        ));
                    }
                    for expr in stmt_exprs(stmt) {
                        for_each_expr(expr, &mut |node| match node {
                            Expr::Yield(_) | Expr::YieldFrom(_) => {
                                issues.push(issue_at(
                                    "python:S2711",
                                    "Move this 'yield' into a function; it appears outside one.",
                                    node.range(),
                                    index,
                                    source,
                                ));
                            }
                            _ => {}
                        });
                    }
                }
                for body in child_bodies(stmt) {
                    visit_scopes_for_yields(body, function_depth, issues, index, source);
                }
            }
        }
    }
}

// --- python:S2712 — return with a value in a generator -------------------------

fn check_generator_return_values(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::FunctionDef(function) = stmt else {
            return;
        };
        let mut generates = false;
        for_each_stmt_in_scope(&function.body, &mut |inner| {
            for expr in stmt_exprs(inner) {
                for_each_expr(expr, &mut |node| {
                    generates |= matches!(node, Expr::Yield(_) | Expr::YieldFrom(_));
                });
            }
        });
        if !generates {
            return;
        }
        for_each_stmt_in_scope(&function.body, &mut |inner| {
            if let Stmt::Return(returned) = inner
                && let Some(value) = returned.value.as_deref()
                && !is_none_literal(value)
            {
                issues.push(issue_at(
                    "python:S2712",
                    "Generators may only return 'None'; remove this returned value.",
                    returned.range(),
                    index,
                    source,
                ));
            }
        });
    });
    issues
}

// --- python:S5899 — unreachable test methods ------------------------------------

fn is_test_case_base(expr: &Expr) -> bool {
    let tail = match expr {
        Expr::Name(name) => Some(name.id.as_str()),
        Expr::Attribute(attribute) => Some(attribute.attr.as_str()),
        _ => None,
    };
    matches!(tail, Some(base) if base.ends_with("TestCase"))
}

fn check_unreachable_test_methods(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::ClassDef(class) = stmt else { return };
        if !class.bases().iter().any(is_test_case_base) {
            return;
        }
        for member in &class.body {
            if let Stmt::FunctionDef(function) = member {
                let name = function.name.as_str();
                if name.contains("test") && !name.starts_with("test") {
                    issues.push(issue_at(
                        "python:S5899",
                        "Rename this method to start with 'test' or remove it; test runners will not discover it.",
                        function.name.range(),
                        index,
                        source,
                    ));
                }
            }
        }
    });
    issues
}

// --- python:S5915 — assertion at end of except block ---------------------------

fn is_unittest_assert_call(stmt: &Stmt) -> bool {
    let Stmt::Expr(value) = stmt else {
        return false;
    };
    let Expr::Call(call) = value.value.as_ref() else {
        return false;
    };
    match call.func.as_ref() {
        Expr::Name(name) => name.id.as_str().starts_with("assert"),
        Expr::Attribute(attribute) => attribute.attr.as_str().starts_with("assert"),
        _ => false,
    }
}

fn check_assertion_at_end_of_except(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::Try(try_stmt) = stmt else { return };
        for handler in &try_stmt.handlers {
            let ExceptHandler::ExceptHandler(inner) = handler;
            if let Some(last) = inner.body.last()
                && is_unittest_assert_call(last)
            {
                issues.push(issue_at(
                    "python:S5915",
                    "Asserting at the end of an 'except' block masks the original exception.",
                    last.range(),
                    index,
                    source,
                ));
            }
        }
    });
    issues
}

// --- python:S5780 — duplicate dict literal keys ---------------------------------

fn check_duplicate_dict_keys(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Expr::Dict(dict) = expr else { return };
        let mut seen = std::collections::HashSet::new();
        for item in &dict.items {
            let Some(key) = &item.key else { continue };
            let Some(canonical) = constant_literal_text(key) else {
                continue;
            };
            if !seen.insert(canonical) {
                issues.push(issue_at(
                    "python:S5780",
                    "Change this duplicate key; it overrides an earlier entry.",
                    key.range(),
                    index,
                    source,
                ));
            }
        }
    });
    issues
}

// --- python:S5781 — duplicate set literal values ---------------------------------

fn check_duplicate_set_elements(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Expr::Set(set) = expr else { return };
        let mut seen = std::collections::HashSet::new();
        for element in &set.elts {
            let Some(canonical) = constant_literal_text(element) else {
                continue;
            };
            if !seen.insert(canonical) {
                issues.push(issue_at(
                    "python:S5781",
                    "Remove this duplicate element.",
                    element.range(),
                    index,
                    source,
                ));
            }
        }
    });
    issues
}

// --- python:S7498 — literal syntax for empty collections ----------------------

fn check_empty_collection_constructors(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Expr::Call(call) = expr else { return };
        if !call.arguments.args.is_empty() {
            return;
        }
        let literal_shaped = matches!(
            called_name(&call.func),
            Some("list" | "set" | "tuple" | "dict")
        ) && (call.arguments.keywords.is_empty()
            || called_name(&call.func) == Some("dict")
                && call
                    .arguments
                    .keywords
                    .iter()
                    .all(|keyword| keyword.arg.is_some()));
        if literal_shaped {
            issues.push(issue_at(
                "python:S7498",
                "Replace this call with the equivalent collection literal.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- python:S7496 — constructor wrapping an existing literal/comprehension ----

fn wrapping_redundancy(func_name: &str, argument: &Expr) -> bool {
    match func_name {
        "list" => matches!(argument, Expr::List(_) | Expr::ListComp(_)),
        "set" => matches!(argument, Expr::Set(_) | Expr::SetComp(_)),
        "dict" => matches!(argument, Expr::Dict(_) | Expr::DictComp(_)),
        _ => false,
    }
}

fn check_wrapping_collection_constructors(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Expr::Call(call) = expr else { return };
        let Some(name) = called_name(&call.func) else {
            return;
        };
        if call.arguments.keywords.is_empty()
            && let [only] = &call.arguments.args[..]
            && wrapping_redundancy(name, only)
        {
            issues.push(issue_at(
                "python:S7496",
                "Use the inner literal or comprehension directly; this wrapping is redundant.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- python:S7494 — comprehension over a generator expression -----------------

/// `(name, sole positional argument)` for calls shaped `name(x)` without
/// keywords.
fn single_positional_call<'a>(expr: &'a Expr, name: &str) -> Option<&'a Expr> {
    match expr {
        Expr::Call(call)
            if called_name(&call.func) == Some(name)
                && call.arguments.args.len() == 1
                && call.arguments.keywords.is_empty() =>
        {
            Some(&call.arguments.args[0])
        }
        _ => None,
    }
}

fn check_generator_into_constructor(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        if matches!(expr, Expr::Call(call) if matches!(called_name(&call.func), Some("list" | "set")))
            && let Some(argument) =
                single_positional_call(expr, "list").or_else(|| single_positional_call(expr, "set"))
            && matches!(argument, Expr::Generator(_))
        {
            issues.push(issue_at(
                "python:S7494",
                "Use a comprehension instead of passing a generator expression here.",
                expr.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- python:S7500 — copy-only comprehensions -----------------------------------

fn check_copy_only_comprehensions(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| match expr {
        Expr::ListComp(comp) => flag_copy_only(
            comp.elt.as_ref(),
            &comp.generators,
            comp.range(),
            &mut issues,
            index,
            source,
        ),
        Expr::SetComp(comp) => flag_copy_only(
            comp.elt.as_ref(),
            &comp.generators,
            comp.range(),
            &mut issues,
            index,
            source,
        ),
        _ => {}
    });
    issues
}

fn flag_copy_only(
    element: &Expr,
    generators: &[ruff_python_ast::Comprehension],
    range: TextRange,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    let [generator] = generators else { return };
    if generator.ifs.is_empty() && exprs_textually_equal(element, &generator.target, source) {
        issues.push(issue_at(
            "python:S7500",
            "Copy the iterable directly instead of using a comprehension that only renames.",
            range,
            index,
            source,
        ));
    }
}

// --- python:S7504 — list() when iterating ---------------------------------------

fn check_list_wrapped_iteration(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::For(for_stmt) = stmt
            && is_call_to(&for_stmt.iter, "list")
        {
            issues.push(issue_at(
                "python:S7504",
                "Iterate over the iterable directly; wrapping it in 'list()' is unnecessary.",
                for_stmt.iter.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- python:S7505 — map with lambda ----------------------------------------------

fn check_map_lambda_calls(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Expr::Call(call) = expr else { return };
        if called_name(&call.func) == Some("map")
            && call
                .arguments
                .args
                .first()
                .is_some_and(|first| matches!(first, Expr::Lambda(_)))
        {
            issues.push(issue_at(
                "python:S7505",
                "Replace this 'map' call with a comprehension.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- python:S7506 — static value in dict comprehension ---------------------------

/// Constant expression trees: literals and pure operators only.
fn is_constant_expression(expr: &Expr) -> bool {
    let mut constant = true;
    for_each_expr(expr, &mut |node| {
        constant &= matches!(
            node,
            Expr::NoneLiteral(_)
                | Expr::BooleanLiteral(_)
                | Expr::NumberLiteral(_)
                | Expr::StringLiteral(_)
                | Expr::BytesLiteral(_)
                | Expr::EllipsisLiteral(_)
                | Expr::Tuple(_)
                | Expr::List(_)
                | Expr::Set(_)
                | Expr::UnaryOp(_)
                | Expr::BinOp(_)
                | Expr::BoolOp(_)
                | Expr::Compare(_)
        );
    });
    constant
}

fn check_constant_dict_comprehension_values(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        if let Expr::DictComp(comp) = expr
            && is_constant_expression(&comp.value)
        {
            issues.push(issue_at(
                "python:S7506",
                "Use 'dict.fromkeys' to build a mapping with a constant value.",
                comp.value.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- python:S7507 — defaultdict default_factory keyword --------------------------

fn check_defaultdict_keyword_factory(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Expr::Call(call) = expr else { return };
        if called_name(&call.func) != Some("defaultdict") {
            return;
        }
        for keyword in &call.arguments.keywords {
            if keyword
                .arg
                .as_ref()
                .is_some_and(|arg| arg.as_str() == "default_factory")
            {
                issues.push(issue_at(
                    "python:S7507",
                    "Pass the default factory positionally; 'default_factory' is not a valid keyword.",
                    keyword.range(),
                    index,
                    source,
                ));
            }
        }
    });
    issues
}

// --- python:S7508 — redundant identical nested constructors ----------------------

/// Name of a collection-constructor call (`list`, `set`, `tuple`, `frozenset`).
fn constructor_name(expr: &Expr) -> Option<&str> {
    let Expr::Call(call) = expr else { return None };
    let name = called_name(&call.func)?;
    matches!(name, "list" | "set" | "tuple" | "frozenset").then_some(name)
}
fn check_nested_identical_constructors(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Some(outer_name) = constructor_name(expr) else {
            return;
        };
        let Some(outer_argument) = single_positional_call(expr, outer_name) else {
            return;
        };
        if constructor_name(outer_argument) == Some(outer_name) {
            issues.push(issue_at(
                "python:S7508",
                "Remove the redundant nested call; the outer constructor adds nothing.",
                expr.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- python:S7510/S7511/S7516 — sorted/reversed call shapes ----------------------

fn check_sorted_reversed_shapes(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        // S7510: reversed(sorted(x))
        if let Some(argument) = single_positional_call(expr, "reversed")
            && single_positional_call(argument, "sorted").is_some()
        {
            issues.push(issue_at(
                "python:S7510",
                "Sort descending directly with 'sorted(..., reverse=True)'.",
                expr.range(),
                index,
                source,
            ));
            return;
        }
        // S7516: set(sorted(x))
        if let Some(argument) = single_positional_call(expr, "set")
            && single_positional_call(argument, "sorted").is_some()
        {
            issues.push(issue_at(
                "python:S7516",
                "Sorting before 'set' is pointless; the order is discarded.",
                expr.range(),
                index,
                source,
            ));
            return;
        }
        // S7511: set(reversed(x)) / sorted(reversed(x)) / reversed(reversed(x))
        for wrapper in ["set", "sorted"] {
            if let Some(argument) = single_positional_call(expr, wrapper)
                && single_positional_call(argument, "reversed").is_some()
            {
                issues.push(issue_at(
                    "python:S7511",
                    "The 'reversed' call has no effect on the result here.",
                    expr.range(),
                    index,
                    source,
                ));
                return;
            }
        }
        if let Some(argument) = single_positional_call(expr, "reversed")
            && single_positional_call(argument, "reversed").is_some()
        {
            issues.push(issue_at(
                "python:S7511",
                "The 'reversed' call has no effect on the result here.",
                expr.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- python:S7517 — manual key/value iteration ------------------------------------

fn check_manual_key_iteration(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::For(for_stmt) = stmt else { return };
        let Expr::Name(key) = for_stmt.target.as_ref() else {
            return;
        };
        let dict_text = expr_normalized_text(&for_stmt.iter, source);
        for_each_stmt_expr(&for_stmt.body, &mut |expr| {
            if let Expr::Subscript(subscript) = expr
                && expr_normalized_text(&subscript.value, source) == dict_text
                && matches!(subscript.slice.as_ref(), Expr::Name(lookup) if lookup.id.as_str() == key.id.as_str())
            {
                issues.push(issue_at(
                    "python:S7517",
                    "Use '.items()' instead of indexing with the loop variable.",
                    subscript.range(),
                    index,
                    source,
                ));
            }
        });
    });
    issues
}

// --- python:S7519 — constant-populated dict built in a loop ------------------------

fn check_constant_populated_dict_loop(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::For(for_stmt) = stmt else { return };
        if for_stmt.body.is_empty() {
            return;
        }
        let mut constant: Option<String> = None;
        let all_constant_assignments = for_stmt.body.iter().all(|inner| {
            let Stmt::Assign(assign) = inner else {
                return false;
            };
            let [Expr::Subscript(subscript)] = &assign.targets[..] else {
                return false;
            };
            matches!(subscript.slice.as_ref(), Expr::Name(_))
                && matches!(subscript.value.as_ref(), Expr::Name(_))
                && is_constant_expression(&assign.value)
        }) && for_stmt.body.iter().all(|inner| {
            let Stmt::Assign(assign) = inner else {
                return false;
            };
            let normalized = expr_normalized_text(&assign.value, source);
            match &constant {
                None => {
                    constant = Some(normalized);
                    true
                }
                Some(existing) => *existing == normalized,
            }
        });
        if all_constant_assignments {
            issues.push(issue_at(
                "python:S7519",
                "Populate this dictionary with 'dict.fromkeys' instead of assigning a constant in a loop.",
                for_stmt.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- python:S7512 — items() when only keys are needed -------------------------------

fn check_items_only_keys_needed(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::For(for_stmt) = stmt else { return };
        let Expr::Tuple(tuple) = for_stmt.target.as_ref() else {
            return;
        };
        let [Expr::Name(_), Expr::Name(value)] = &tuple.elts[..] else {
            return;
        };
        let items_call = matches!(
            for_stmt.iter.as_ref(),
            Expr::Call(call) if matches!(call.func.as_ref(), Expr::Attribute(attribute) if attribute.attr.as_str() == "items")
        );
        if items_call && !stmts_load_any_name(&for_stmt.body, &[value.id.to_string()]) {
            issues.push(issue_at(
                "python:S7512",
                "Iterate over the dictionary directly; the value is not used.",
                for_stmt.iter.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// ---------------------------------------------------------------------------
// Battery aggregation: every Tier-A entry #48–#110 in artifact order.
// ---------------------------------------------------------------------------

fn check_tier_a_battery(parsed: &Parsed<ModModule>, index: &LineIndex, source: &str) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_needless_pass(parsed, index, source));
    issues.extend(check_dunder_all_strings(parsed, index, source));
    issues.extend(check_loop_else_without_break(parsed, index, source));
    issues.extend(check_nested_conditional_expressions(parsed, index, source));
    issues.extend(check_redundant_jump_statements(parsed, index, source));
    issues.extend(check_identical_if_else_branches(parsed, index, source));
    issues.extend(check_meaningless_size_comparisons(parsed, index, source));
    issues.extend(check_unreachable_code(parsed, index, source));
    issues.extend(check_identical_operands(parsed, index, source));
    issues.extend(check_duplicate_conditions(parsed, index, source));
    issues.extend(check_duplicate_branches(parsed, index, source));
    issues.extend(check_inverted_boolean_checks(parsed, index, source));
    issues.extend(check_self_assignment(parsed, index, source));
    issues.extend(check_wildcard_imports(parsed, index, source));
    issues.extend(check_doubled_prefix_operators(parsed, index, source));
    issues.extend(check_confusing_walrus_placement(parsed, index, source));
    issues.extend(check_constant_none_comparisons(parsed, index, source));
    issues.extend(check_fresh_object_identity_checks(parsed, index, source));
    issues.extend(check_tuple_assertions(parsed, index, source));
    issues.extend(check_type_equality_comparisons(parsed, index, source));
    issues.extend(check_lambda_assignments(parsed, index, source));
    issues.extend(check_boundary_slice_comparisons(parsed, index, source));
    issues.extend(check_float_equality_comparisons(parsed, index, source));
    issues.extend(check_no_effect_statements(parsed, index, source));
    issues.extend(check_exit_signatures(parsed, index, source));
    issues.extend(check_init_return_values(parsed, index, source));
    issues.extend(check_only_reraise_handlers(parsed, index, source));
    issues.extend(check_notimplemented_raises(parsed, index, source));
    issues.extend(check_methods_missing_parameters(parsed, index, source));
    issues.extend(check_instance_self_parameters(parsed, index, source));
    issues.extend(check_special_method_arities(parsed, index, source));
    issues.extend(check_property_accessor_arities(parsed, index, source));
    issues.extend(check_exception_inheritance(parsed, index, source));
    issues.extend(check_boolean_except_clauses(parsed, index, source));
    issues.extend(check_raise_and_jump_flow(parsed, index, source));
    issues.extend(check_exit_reraises_argument(parsed, index, source));
    issues.extend(check_swallowed_system_exit(parsed, index, source));
    issues.extend(check_closure_captures_loop_variable(parsed, index, source));
    issues.extend(check_classmethod_parameter_names(parsed, index, source));
    issues.extend(check_yield_return_outside_function(parsed, index, source));
    issues.extend(check_generator_return_values(parsed, index, source));
    issues.extend(check_unreachable_test_methods(parsed, index, source));
    issues.extend(check_assertion_at_end_of_except(parsed, index, source));
    issues.extend(check_duplicate_dict_keys(parsed, index, source));
    issues.extend(check_duplicate_set_elements(parsed, index, source));
    issues.extend(check_empty_collection_constructors(parsed, index, source));
    issues.extend(check_wrapping_collection_constructors(
        parsed, index, source,
    ));
    issues.extend(check_generator_into_constructor(parsed, index, source));
    issues.extend(check_copy_only_comprehensions(parsed, index, source));
    issues.extend(check_list_wrapped_iteration(parsed, index, source));
    issues.extend(check_map_lambda_calls(parsed, index, source));
    issues.extend(check_constant_dict_comprehension_values(
        parsed, index, source,
    ));
    issues.extend(check_defaultdict_keyword_factory(parsed, index, source));
    issues.extend(check_nested_identical_constructors(parsed, index, source));
    issues.extend(check_sorted_reversed_shapes(parsed, index, source));
    issues.extend(check_manual_key_iteration(parsed, index, source));
    issues.extend(check_constant_populated_dict_loop(parsed, index, source));
    issues.extend(check_items_only_keys_needed(parsed, index, source));
    issues
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{AnalyzerOptions, analyze};

    fn pos(line: u32, column: u32) -> hoonarqube_ir::Pos {
        hoonarqube_ir::Pos { line, column }
    }

    fn issue(
        rule_key: &str,
        message: &str,
        start: (u32, u32),
        end: (u32, u32),
    ) -> hoonarqube_ir::Issue {
        hoonarqube_ir::Issue {
            rule_key: rule_key.to_string(),
            message: message.to_string(),
            range: hoonarqube_ir::Range {
                start: pos(start.0, start.1),
                end: pos(end.0, end.1),
            },
        }
    }

    #[test]
    fn parsing_errors_are_recovered_from_tolerantly() {
        let report = analyze(
            PathBuf::from("test.py"),
            "def f(:\n    pass",
            &AnalyzerOptions::default(),
        );
        let parsing: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "python:ParsingError")
            .collect();
        // Ruff 0.0.10 tolerant recovery emits exactly these two errors for
        // this input; the analyzer reports one issue per `errors()` entry.
        assert_eq!(parsing.len(), 2);
        assert!(parsing[0].message.contains("Expected"));
    }

    #[test]
    fn nosonar_comment_is_flagged_case_sensitively() {
        let report = analyze(
            PathBuf::from("test.py"),
            "x = 1  # NOSONAR\n",
            &AnalyzerOptions::default(),
        );
        assert_eq!(
            report.issues,
            vec![issue(
                "python:NoSonar",
                "Remove this usage of 'NOSONAR'.",
                (1, 7),
                (1, 16),
            )]
        );

        let lowercase = analyze(
            PathBuf::from("test.py"),
            "x = 1  # nosonar\n",
            &AnalyzerOptions::default(),
        );
        assert!(lowercase.issues.is_empty());
    }

    #[test]
    fn one_statement_per_line_flags_only_second_onwards() {
        let report = analyze(
            PathBuf::from("test.py"),
            "a = 1\nb = 2\nc = 3; d = 4\n",
            &AnalyzerOptions::default(),
        );
        assert_eq!(
            report.issues,
            vec![issue(
                "python:OneStatementPerLine",
                "Only one statement per line is allowed.",
                (3, 7),
                (3, 12),
            )]
        );
    }
    #[test]
    fn line_length_honors_option() {
        let long_121 = format!("x = {}\n", "1".repeat(117));
        // 4 + 117 content chars plus the trailing newline required by S113.
        assert_eq!(long_121.chars().count(), 122);
        let report = analyze(
            PathBuf::from("test.py"),
            &long_121,
            &AnalyzerOptions::default(),
        );
        assert_eq!(report.issues.len(), 1);
        assert_eq!(report.issues[0].rule_key, "python:LineLength");
        assert_eq!(report.issues[0].range.start, pos(1, 0));
        assert_eq!(report.issues[0].range.end, pos(1, 121));

        let long_120 = format!("x = {}\n", "1".repeat(116));
        let clean = analyze(
            PathBuf::from("test.py"),
            &long_120,
            &AnalyzerOptions::default(),
        );
        assert!(clean.issues.is_empty());

        let strict = AnalyzerOptions {
            maximum_line_length: 10,
            ..AnalyzerOptions::default()
        };
        let flagged = analyze(PathBuf::from("test.py"), "x = 12345678\n", &strict);
        assert_eq!(flagged.issues.len(), 1);
        assert_eq!(
            flagged.issues[0].message,
            "This line exceeds the maximum allowed length of 10 characters."
        );
    }

    #[test]
    fn exec_and_print_calls_are_flagged_but_not_attributes() {
        let source = "exec(\"x\")\nprint(\"y\")\nmy_print(\"z\")\nmy_exec(\"w\")\n";
        let report = analyze(
            PathBuf::from("test.py"),
            source,
            &AnalyzerOptions::default(),
        );
        assert_eq!(
            report
                .issues
                .iter()
                .map(|issue| issue.rule_key.as_str())
                .collect::<Vec<_>>(),
            vec!["python:ExecStatementUsage", "python:PrintStatementUsage"]
        );
    }

    #[test]
    fn metrics_count_code_comment_and_blank_lines() {
        let report = analyze(
            PathBuf::from("test.py"),
            "x = 1\n# only a comment\n\n",
            &AnalyzerOptions::default(),
        );
        assert_eq!(
            report.metrics,
            hoonarqube_ir::FileMetrics {
                lines: 3,
                code_lines: 1,
                comment_lines: 1,
            }
        );
    }

    #[test]
    fn issue_positions_are_one_based_line_zero_based_column() {
        let report = analyze(
            PathBuf::from("test.py"),
            "if x:\n  exec(y)\n",
            &AnalyzerOptions::default(),
        );
        assert_eq!(report.issues.len(), 1);
        assert_eq!(report.issues[0].range.start, pos(2, 2));
    }

    #[test]
    fn integration_assembles_full_report_sorted() {
        let source = concat!(
            "import os\n",
            "\n",
            "def greet(name):\n",
            "    # greeting comment\n",
            "    print(\"hello\")\n",
            "    x = 1; y = 2\n",
            "    if name:\n",
            "        exec(\"z = 1\")\n",
            "\n",
            "greet(\"world\")  # NOSONAR here\n",
        );
        let report = analyze(
            PathBuf::from("demo.py"),
            source,
            &AnalyzerOptions::default(),
        );
        assert_eq!(
            report,
            hoonarqube_ir::FileReport {
                path: PathBuf::from("demo.py"),
                language: "python".to_string(),
                issues: vec![
                    issue(
                        "python:PrintStatementUsage",
                        "Remove this usage of 'print'.",
                        (5, 4),
                        (5, 9),
                    ),
                    issue(
                        "python:OneStatementPerLine",
                        "Only one statement per line is allowed.",
                        (6, 11),
                        (6, 16),
                    ),
                    issue(
                        "python:ExecStatementUsage",
                        "Remove this usage of 'exec'.",
                        (8, 8),
                        (8, 12),
                    ),
                    issue(
                        "python:NoSonar",
                        "Remove this usage of 'NOSONAR'.",
                        (10, 16),
                        (10, 30),
                    ),
                ],
                metrics: hoonarqube_ir::FileMetrics {
                    lines: 10,
                    code_lines: 7,
                    comment_lines: 1,
                },
            }
        );
    }

    #[test]
    fn file_must_end_with_newline() {
        let missing = analyze(PathBuf::from("t.py"), "x = 1", &AnalyzerOptions::default());
        assert_eq!(
            missing.issues,
            vec![issue(
                "python:S113",
                "Add a newline character at the end of this file.",
                (1, 0),
                (1, 5),
            )]
        );
        assert!(
            analyze(PathBuf::from("t.py"), "", &AnalyzerOptions::default())
                .issues
                .iter()
                .all(|issue| issue.rule_key != "python:S113")
        );
        assert!(
            analyze(
                PathBuf::from("t.py"),
                "x = 1\n",
                &AnalyzerOptions::default()
            )
            .issues
            .iter()
            .all(|issue| issue.rule_key != "python:S113")
        );
    }

    #[test]
    fn trailing_whitespace_is_flagged_per_line() {
        let report = analyze(
            PathBuf::from("t.py"),
            "a \nb\t\nc\n",
            &AnalyzerOptions::default(),
        );
        let flagged: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "python:S1131")
            .collect();
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start, pos(1, 1));
        assert_eq!(flagged[0].range.end, pos(1, 2));
        assert_eq!(flagged[1].range.start, pos(2, 1));
        assert_eq!(flagged[1].range.end, pos(2, 2));
    }

    #[test]
    fn todo_and_fixme_tags_are_tracked_with_person_reference() {
        let report = analyze(
            PathBuf::from("t.py"),
            "# FIXME fix later\n# TODO (jane) improve\n",
            &AnalyzerOptions::default(),
        );
        assert_eq!(
            report.issues,
            vec![
                issue(
                    "python:S1134",
                    "Resolve this FIXME comment or clarify it with a person reference.",
                    (1, 0),
                    (1, 17),
                ),
                issue(
                    "python:S1707",
                    "Add a person reference such as '(jane)' to this TODO/FIXME comment.",
                    (1, 0),
                    (1, 17),
                ),
                issue(
                    "python:S1135",
                    "Resolve this TODO comment or clarify it with a person reference.",
                    (2, 0),
                    (2, 21),
                ),
            ]
        );
    }

    #[test]
    fn noqa_comments_are_tracked_and_validated() {
        let well_formed = ["# noqa", "# noqa: E501", "# noqa: E501,F841"];
        for source in well_formed {
            let report = analyze(
                PathBuf::from("t.py"),
                &format!("{source}\n"),
                &AnalyzerOptions::default(),
            );
            assert_eq!(report.issues.len(), 1, "source: {source}");
            assert_eq!(report.issues[0].rule_key, "python:S1309");
        }
        for source in ["#noqa", "# noqa : E501", "# noqa: e501"] {
            let report = analyze(
                PathBuf::from("t.py"),
                &format!("{source}\n"),
                &AnalyzerOptions::default(),
            );
            let keys: Vec<_> = report
                .issues
                .iter()
                .map(|issue| issue.rule_key.as_str())
                .collect();
            assert_eq!(
                keys,
                vec!["python:S1309", "python:S7632"],
                "source: {source}"
            );
        }
    }

    #[test]
    fn license_header_is_enforced_only_when_configured() {
        let options = AnalyzerOptions {
            copyright_header_format: "Copyright 2026".to_string(),
            ..AnalyzerOptions::default()
        };
        assert!(
            analyze(PathBuf::from("t.py"), "# Copyright 2026\nx = 1\n", &options)
                .issues
                .is_empty()
        );
        assert!(
            analyze(
                PathBuf::from("t.py"),
                "#!/usr/bin/env python3\n# Copyright 2026\nx = 1\n",
                &options
            )
            .issues
            .is_empty()
        );
        let missing = analyze(PathBuf::from("t.py"), "x = 1\n", &options);
        assert_eq!(
            missing.issues,
            vec![issue(
                "python:S1451",
                "Add or update the copyright header of this file.",
                (1, 0),
                (1, 0)
            )]
        );
        assert!(
            analyze(
                PathBuf::from("t.py"),
                "x = 1\n",
                &AnalyzerOptions::default()
            )
            .issues
            .is_empty()
        );
    }

    #[test]
    fn module_names_must_follow_convention() {
        let flagged = analyze(
            PathBuf::from("my-mod.py"),
            "x = 1\n",
            &AnalyzerOptions::default(),
        );
        assert_eq!(
            flagged
                .issues
                .iter()
                .filter(|issue| issue.rule_key == "python:S1578")
                .count(),
            1
        );
        for name in ["good_mod.py", "GoodMod.py", "__init__.py"] {
            assert!(
                analyze(PathBuf::from(name), "x = 1\n", &AnalyzerOptions::default())
                    .issues
                    .iter()
                    .all(|issue| issue.rule_key != "python:S1578"),
                "name: {name}"
            );
        }
    }

    fn findings<'a>(
        report: &'a hoonarqube_ir::FileReport,
        key: &str,
    ) -> Vec<&'a hoonarqube_ir::Issue> {
        report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == key)
            .collect()
    }

    fn scan(source: &str) -> hoonarqube_ir::FileReport {
        analyze(PathBuf::from("t.py"), source, &AnalyzerOptions::default())
    }

    #[test]
    fn s2772_flags_only_redundant_pass() {
        let flagged = scan("def f():\n    pass\n    return 1\n");
        let found = findings(&flagged, "python:S2772");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 2);
        for clean in ["def f():\n    pass\n", "class A:\n    pass\n    x = 1\n"] {
            assert!(
                findings(&scan(clean), "python:S2772").is_empty(),
                "clean: {clean}"
            );
        }
    }

    #[test]
    fn s2823_requires_string_literals_in_dunder_all() {
        let flagged = scan("__all__ = [\"a\", b]\n");
        let found = findings(&flagged, "python:S2823");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 1);
        for clean in ["__all__ = [\"a\", \"b\"]\n", "__all__ += [\"c\"]\n"] {
            assert!(findings(&scan(clean), "python:S2823").is_empty(), "{clean}");
        }
    }

    #[test]
    fn s2836_flags_loop_else_without_break() {
        let flagged = scan("while x:\n    drain()\nelse:\n    close()\n");
        let found = findings(&flagged, "python:S2836");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 4);
        let clean = "while x:\n    if done(x):\n        break\nelse:\n    close()\n";
        assert!(findings(&scan(clean), "python:S2836").is_empty());
    }

    #[test]
    fn s3358_flags_nested_conditional_expressions() {
        let flagged = scan("v = a if b else c if d else e\n");
        assert_eq!(findings(&flagged, "python:S3358").len(), 1);
        assert!(findings(&scan("v = a if b else e\n"), "python:S3358").is_empty());
    }

    #[test]
    fn s3626_flags_trailing_jump_statements() {
        let cases = [
            ("def f():\n    setup()\n    return\n", 3),
            ("for i in xs:\n    step(i)\n    continue\n", 3),
            ("match x:\n    case 1:\n        break\n", 3),
        ];
        for (source, line) in cases {
            let report = scan(source);
            let found = findings(&report, "python:S3626");
            assert_eq!(found.len(), 1, "{source}");
            assert_eq!(found[0].range.start.line, line);
        }
        let clean = "def f():\n    if a:\n        return 0\n    return 1\n";
        assert!(findings(&scan(clean), "python:S3626").is_empty());
    }

    #[test]
    fn s3923_flags_identical_if_else_branches() {
        let flagged = scan("if a:\n    run()\nelse:\n    run()\n");
        assert_eq!(findings(&flagged, "python:S3923").len(), 1);
        let clean = "if a:\n    run()\nelse:\n    walk()\n";
        assert!(findings(&scan(clean), "python:S3923").is_empty());
    }

    #[test]
    fn s3981_len_zero_comparison_table() {
        for source in [
            "if len(xs) >= 0:\n    show()\n",
            "if 0 <= len(xs):\n    show()\n",
        ] {
            assert_eq!(findings(&scan(source), "python:S3981").len(), 1, "{source}");
        }
        for clean in [
            "if len(xs) == 0:\n    show()\n",
            "if len(xs) < 5:\n    show()\n",
        ] {
            assert!(findings(&scan(clean), "python:S3981").is_empty(), "{clean}");
        }
    }

    #[test]
    fn s1763_flags_statements_after_terminator() {
        let flagged = scan("def f():\n    return 1\n    print(x)\n    y()\n");
        let found = findings(&flagged, "python:S1763");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].range.start.line, 3);
        assert_eq!(found[1].range.start.line, 4);
        let clean = "def f():\n    if a:\n        return 1\n    return 2\n";
        assert!(findings(&scan(clean), "python:S1763").is_empty());
    }

    #[test]
    fn s1764_flags_identical_operands_except_small_ints() {
        assert_eq!(findings(&scan("z = x - x\n"), "python:S1764").len(), 1);
        assert_eq!(findings(&scan("q = x == x\n"), "python:S1764").len(), 1);
        for clean in ["z = x * 2\n", "q = 1 - 1\n"] {
            assert!(findings(&scan(clean), "python:S1764").is_empty(), "{clean}");
        }
    }

    #[test]
    fn s1862_flags_duplicate_conditions_in_chain() {
        let flagged = scan("if a == 1:\n    f()\nelif a == 1:\n    g()\n");
        let found = findings(&flagged, "python:S1862");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 3);
        let clean = "if a == 1:\n    f()\nelif a == 2:\n    g()\n";
        assert!(findings(&scan(clean), "python:S1862").is_empty());
    }

    #[test]
    fn s1871_flags_duplicate_branch_bodies() {
        let chain = scan("if a == 1:\n    do(x)\nelif a == 2:\n    do(x)\n");
        let found = findings(&chain, "python:S1871");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 4);
        let handlers =
            scan("try:\n    risky()\nexcept A:\n    handle()\nexcept B:\n    handle()\n");
        assert_eq!(findings(&handlers, "python:S1871").len(), 1);
        let clean = "if a == 1:\n    do(x)\nelif a == 2:\n    do(y)\n";
        assert!(findings(&scan(clean), "python:S1871").is_empty());
    }

    #[test]
    fn s1940_flags_negated_comparisons() {
        assert_eq!(
            findings(&scan("ok = not (a == b)\n"), "python:S1940").len(),
            1
        );
        assert!(findings(&scan("fine = not (a and b)\n"), "python:S1940").is_empty());
    }

    #[test]
    fn s1656_flags_self_assignment() {
        assert_eq!(findings(&scan("x = x\n"), "python:S1656").len(), 1);
        assert_eq!(findings(&scan("x.y = x.y\n"), "python:S1656").len(), 1);
        assert!(findings(&scan("x = y\n"), "python:S1656").is_empty());
    }

    #[test]
    fn s2208_flags_wildcard_imports() {
        assert_eq!(
            findings(&scan("from m import *\n"), "python:S2208").len(),
            1
        );
        assert!(findings(&scan("from m import thing\n"), "python:S2208").is_empty());
    }

    #[test]
    fn s2761_flags_doubled_prefix_operators() {
        assert_eq!(
            findings(&scan("b = not not flag\n"), "python:S2761").len(),
            1
        );
        assert_eq!(findings(&scan("c = ~~bits\n"), "python:S2761").len(), 1);
        assert!(findings(&scan("flip = -(-amount)\n"), "python:S2761").is_empty());
    }

    #[test]
    fn s5685_flags_confusing_walrus_positions() {
        assert_eq!(
            findings(&scan("vals = [y := get(y) for y in ys]\n"), "python:S5685").len(),
            1
        );
        assert_eq!(
            findings(&scan("mid = a < (b := c) < d\n"), "python:S5685").len(),
            1
        );
        assert!(
            findings(
                &scan("kept = [y for y in ys if (mark := y)]\n"),
                "python:S5685"
            )
            .is_empty()
        );
    }

    #[test]
    fn s5727_flags_constant_none_comparisons() {
        assert_eq!(
            findings(&scan("same = None == None\n"), "python:S5727").len(),
            1
        );
        assert_eq!(
            findings(&scan("odd = \"x\" == None\n"), "python:S5727").len(),
            1
        );
        assert!(findings(&scan("maybe = x == None\n"), "python:S5727").is_empty());
    }

    #[test]
    fn s5796_flags_identity_on_fresh_objects() {
        assert_eq!(
            findings(&scan("never = [] is []\n"), "python:S5796").len(),
            1
        );
        assert_eq!(
            findings(&scan("fresh = list() is other\n"), "python:S5796").len(),
            1
        );
        assert!(findings(&scan("ref = a is b\n"), "python:S5796").is_empty());
    }

    #[test]
    fn s5905_flags_nonempty_tuple_assertions() {
        let flagged = scan("assert (False, \"why\")\n");
        assert_eq!(findings(&flagged, "python:S5905").len(), 1);
        for clean in ["assert ()\n", "assert condition\n"] {
            assert!(findings(&scan(clean), "python:S5905").is_empty(), "{clean}");
        }
    }

    #[test]
    fn s6660_prefers_isinstance_over_type_equality() {
        assert_eq!(
            findings(&scan("exact = type(x) is int\n"), "python:S6660").len(),
            1
        );
        assert!(findings(&scan("safe = isinstance(x, int)\n"), "python:S6660").is_empty());
    }

    #[test]
    fn s6661_flags_lambdas_assigned_to_names() {
        assert_eq!(
            findings(&scan("handler = lambda e: str(e)\n"), "python:S6661").len(),
            1
        );
        assert!(
            findings(
                &scan("def handler(e):\n    return str(e)\n"),
                "python:S6661"
            )
            .is_empty()
        );
    }

    #[test]
    fn s6659_prefers_startswith_endswith_over_slices() {
        assert_eq!(
            findings(&scan("head = name[:2] == \"ab\"\n"), "python:S6659").len(),
            1
        );
        assert_eq!(
            findings(&scan("tail = name[-2:] == \"cd\"\n"), "python:S6659").len(),
            1
        );
        assert!(findings(&scan("mid = name[1:2] == \"b\"\n"), "python:S6659").is_empty());
    }

    #[test]
    fn s1244_flags_exact_float_equality_only() {
        assert_eq!(
            findings(&scan("close = 0.1 + 0.2 == 0.3\n"), "python:S1244").len(),
            1
        );
        for clean in ["cmp = 0.1 < 0.2\n", "ieq = 1 == 2\n"] {
            assert!(findings(&scan(clean), "python:S1244").is_empty(), "{clean}");
        }
    }

    #[test]
    fn s905_flags_pure_expression_statements_but_not_docstrings() {
        let flagged = scan("\"\"\"Module doc.\"\"\"\n42\nx == 1\nrun(x)\n");
        let found = findings(&flagged, "python:S905");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].range.start.line, 2);
        assert_eq!(found[1].range.start.line, 3);
    }

    #[test]
    fn s2733_checks_exit_signature_completeness() {
        let flagged =
            scan("class C:\n    def __exit__(self, kind, value):\n        return False\n");
        assert_eq!(findings(&flagged, "python:S2733").len(), 1);
        let clean = "class C:\n    def __exit__(self, kind, value, trace):\n        return False\n";
        assert!(findings(&scan(clean), "python:S2733").is_empty());
    }

    #[test]
    fn s2734_flags_init_returning_value() {
        let flagged =
            scan("class C:\n    def __init__(self):\n        self.x = 1\n        return 5\n");
        let found = findings(&flagged, "python:S2734");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 4);
        let clean = "class C:\n    def __init__(self):\n        self.x = 1\n        return None\n";
        assert!(findings(&scan(clean), "python:S2734").is_empty());
    }

    #[test]
    fn s2737_flags_handlers_that_only_reraise() {
        let flagged = scan("try:\n    risky()\nexcept ValueError:\n    raise\n");
        assert_eq!(findings(&flagged, "python:S2737").len(), 1);
        let clean = "try:\n    risky()\nexcept ValueError:\n    log()\n    raise\n";
        assert!(findings(&scan(clean), "python:S2737").is_empty());
    }

    #[test]
    fn s5712_prefers_returning_notimplemented() {
        let flagged =
            scan("class P:\n    def __eq__(self, other):\n        raise NotImplementedError\n");
        assert_eq!(findings(&flagged, "python:S5712").len(), 1);
        let clean = "class P:\n    def __eq__(self, other):\n        return NotImplemented\n";
        assert!(findings(&scan(clean), "python:S5712").is_empty());
    }

    #[test]
    fn s5719_requires_positional_parameter_on_methods() {
        let flagged = scan("class C:\n    def method():\n        return 1\n");
        assert_eq!(findings(&flagged, "python:S5719").len(), 1);
        let static_clean = "class C:\n    @staticmethod\n    def util():\n        return 1\n";
        assert!(findings(&scan(static_clean), "python:S5719").is_empty());
        let bound_clean = "class C:\n    def method(self):\n        return 1\n";
        assert!(findings(&scan(bound_clean), "python:S5719").is_empty());
    }

    #[test]
    fn s5720_requires_self_first_for_instance_methods() {
        let flagged = scan("class C:\n    def show(this_one):\n        return this_one\n");
        assert_eq!(findings(&flagged, "python:S5720").len(), 1);
        let classmethod_clean =
            "class C:\n    @classmethod\n    def build(cls):\n        return cls\n";
        assert!(findings(&scan(classmethod_clean), "python:S5720").is_empty());
    }

    #[test]
    fn s5722_flags_missing_special_method_parameters() {
        let flagged = scan("class C:\n    def __lt__(self):\n        return NotImplemented\n");
        assert_eq!(findings(&flagged, "python:S5722").len(), 1);
        let clean = "class C:\n    def __lt__(self, other):\n        return NotImplemented\n";
        assert!(findings(&scan(clean), "python:S5722").is_empty());
    }

    #[test]
    fn s5724_checks_property_accessor_arity_exactly() {
        let flagged =
            scan("class C:\n    @property\n    def size(self, extra):\n        return 1\n");
        assert_eq!(findings(&flagged, "python:S5724").len(), 1);
        for clean in [
            "class C:\n    @property\n    def size(self):\n        return 1\n",
            "class C:\n    @size.setter\n    def size(self, value):\n        self._size = value\n",
        ] {
            assert!(findings(&scan(clean), "python:S5724").is_empty(), "{clean}");
        }
    }

    #[test]
    fn s5709_requires_exception_base_for_exception_named_classes() {
        assert_eq!(
            findings(&scan("class AppError:\n    pass\n"), "python:S5709").len(),
            1
        );
        for clean in [
            "class AppError(Exception):\n    pass\n",
            "class Plain:\n    pass\n",
        ] {
            assert!(findings(&scan(clean), "python:S5709").is_empty(), "{clean}");
        }
    }

    #[test]
    fn s5714_flags_boolean_except_specifications() {
        let flagged = scan("try:\n    run()\nexcept (A or B):\n    stop()\n");
        assert_eq!(findings(&flagged, "python:S5714").len(), 1);
        let clean = "try:\n    run()\nexcept (A, B):\n    stop()\n";
        assert!(findings(&scan(clean), "python:S5714").is_empty());
    }

    #[test]
    fn s5704_and_s5747_classify_bare_raise_by_context() {
        let in_finally = scan(
            "def f():\n    try:\n        work()\n    finally:\n        cleanup()\n        raise\n",
        );
        assert_eq!(findings(&in_finally, "python:S5704").len(), 1);
        let outside = scan("def f():\n    if ready:\n        raise\n");
        assert_eq!(findings(&outside, "python:S5747").len(), 1);
        let in_except = scan("try:\n    work()\nexcept ValueError:\n    raise\n");
        assert!(findings(&in_except, "python:S5704").is_empty());
        assert!(findings(&in_except, "python:S5747").is_empty());
    }

    #[test]
    fn s1143_flags_jump_statements_inside_finally() {
        let flagged = scan("def f():\n    try:\n        load()\n    finally:\n        return 1\n");
        assert_eq!(findings(&flagged, "python:S1143").len(), 1);
        let clean = "def f():\n    try:\n        load()\n    finally:\n        release()\n";
        assert!(findings(&scan(clean), "python:S1143").is_empty());
    }

    #[test]
    fn s1716_flags_break_continue_without_enclosing_loop() {
        assert_eq!(
            findings(&scan("def f():\n    break\n"), "python:S1716").len(),
            1
        );
        let clean = "for _ in xs:\n    break\n";
        assert!(findings(&scan(clean), "python:S1716").is_empty());
    }

    #[test]
    fn s5706_flags_exit_reraising_its_arguments() {
        let flagged = scan(concat!(
            "class C:\n",
            "    def __exit__(self, kind, value, trace):\n",
            "        cleanup(value)\n",
            "        raise value\n"
        ));
        assert_eq!(findings(&flagged, "python:S5706").len(), 1);
        let clean = concat!(
            "class C:\n",
            "    def __exit__(self, kind, value, trace):\n",
            "        cleanup(value)\n",
            "        return False\n"
        );
        assert!(findings(&scan(clean), "python:S5706").is_empty());
    }

    #[test]
    fn s5754_requires_systemexit_reraise() {
        let flagged = scan("try:\n    run_app()\nexcept SystemExit:\n    cleanup()\n");
        assert_eq!(findings(&flagged, "python:S5754").len(), 1);
        let clean = "try:\n    run_app()\nexcept ValueError:\n    cleanup()\n";
        assert!(findings(&scan(clean), "python:S5754").is_empty());
    }

    #[test]
    fn s1515_flags_closures_capturing_loop_variables() {
        let flagged = scan("callbacks = []\nfor i in range(3):\n    callbacks.append(lambda: i)\n");
        let found = findings(&flagged, "python:S1515");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 3);
        let clean = "callbacks = []\nfor i in range(3):\n    callbacks.append(lambda v: v)\n";
        assert!(findings(&scan(clean), "python:S1515").is_empty());
    }

    #[test]
    fn s2710_requires_cls_naming_for_classmethods() {
        let flagged =
            scan("class C:\n    @classmethod\n    def make(other):\n        return other\n");
        assert_eq!(findings(&flagged, "python:S2710").len(), 1);
        let clean = "class C:\n    @classmethod\n    def make(cls):\n        return cls\n";
        assert!(findings(&scan(clean), "python:S2710").is_empty());
    }

    #[test]
    fn s2711_flags_yield_outside_functions() {
        let flagged = scan("yield 1\n");
        assert_eq!(findings(&flagged, "python:S2711").len(), 1);
        let clean = "def g():\n    yield 1\n";
        assert!(findings(&scan(clean), "python:S2711").is_empty());
    }

    #[test]
    fn s2712_flags_generator_returning_value() {
        let flagged = scan("def gen():\n    yield 1\n    return 5\n");
        let found = findings(&flagged, "python:S2712");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 3);
        let clean = "def gen():\n    yield 1\n    return\n";
        assert!(findings(&scan(clean), "python:S2712").is_empty());
    }

    #[test]
    fn s5899_flags_test_methods_runners_cannot_discover() {
        let flagged = scan("class T(TestCase):\n    def my_test(self):\n        pass\n");
        assert_eq!(findings(&flagged, "python:S5899").len(), 1);
        for clean in [
            "class T(TestCase):\n    def test_it(self):\n        pass\n",
            "class U:\n    def my_test(self):\n        pass\n",
        ] {
            assert!(findings(&scan(clean), "python:S5899").is_empty(), "{clean}");
        }
    }

    #[test]
    fn s5915_flags_unittest_assertion_closing_except_block() {
        let flagged =
            scan("try:\n    parse(raw)\nexcept ValueError:\n    self.assertEqual(got, want)\n");
        assert_eq!(findings(&flagged, "python:S5915").len(), 1);
        let clean = "try:\n    parse(raw)\nexcept ValueError:\n    log(got)\nassert want == got\n";
        assert!(findings(&scan(clean), "python:S5915").is_empty());
    }

    #[test]
    fn s5780_flags_duplicate_dict_literal_keys() {
        let flagged = scan("cfg = {\"retries\": 1, \"retries\": 2}\n");
        assert_eq!(findings(&flagged, "python:S5780").len(), 1);
        let clean = "cfg = {\"retries\": 1, \"timeout\": 2}\n";
        assert!(findings(&scan(clean), "python:S5780").is_empty());
    }

    #[test]
    fn s5781_flags_duplicate_set_literal_elements() {
        assert_eq!(
            findings(&scan("singles = {1, 1}\n"), "python:S5781").len(),
            1
        );
        assert!(findings(&scan("pair = {1, 2}\n"), "python:S5781").is_empty());
    }

    #[test]
    fn s7498_prefers_literal_syntax_for_empty_collections() {
        let flagged = scan("empty = dict()\nnamed = dict(a=1)\nseq = list()\n");
        assert_eq!(findings(&flagged, "python:S7498").len(), 3);
        for clean in ["first = {}\n", "second = []\n"] {
            assert!(findings(&scan(clean), "python:S7498").is_empty(), "{clean}");
        }
    }

    #[test]
    fn s7496_flags_redundant_wrapping_constructors() {
        let flagged = scan(
            "wrapped = list([1, 2])\nsets = set({1})\nmaps = dict({\"a\": 1})\nconv = list((4, 5))\n",
        );
        assert_eq!(findings(&flagged, "python:S7496").len(), 3);
        // The tuple conversion is a real type change and stays unflagged.
        assert_eq!(
            flagged
                .issues
                .iter()
                .filter(|i| i.range.start.line == 4)
                .count(),
            0
        );
    }

    #[test]
    fn s7494_prefers_comprehension_over_wrapped_generator() {
        assert_eq!(
            findings(&scan("evens = list(x for x in xs)\n"), "python:S7494").len(),
            1
        );
        assert!(findings(&scan("odds = [x for x in xs]\n"), "python:S7494").is_empty());
    }

    #[test]
    fn s7500_flags_only_element_renaming_comprehensions() {
        assert_eq!(
            findings(&scan("copy = [item for item in items]\n"), "python:S7500").len(),
            1
        );
        for clean in [
            "shaped = [render(item) for item in items]\n",
            "kept = [item for item in items if item]\n",
        ] {
            assert!(findings(&scan(clean), "python:S7500").is_empty(), "{clean}");
        }
    }

    #[test]
    fn s7504_flags_iteration_over_list_wrapped_iterable() {
        let flagged = scan("for item in list(items):\n    show(item)\n");
        assert_eq!(findings(&flagged, "python:S7504").len(), 1);
        let clean = "for item in items:\n    show(item)\n";
        assert!(findings(&scan(clean), "python:S7504").is_empty());
    }

    #[test]
    fn s7505_flags_map_calls_with_lambda() {
        assert_eq!(
            findings(
                &scan("doubled = map(lambda v: v * 2, values)\n"),
                "python:S7505"
            )
            .len(),
            1
        );
        assert!(findings(&scan("names = map(str, values)\n"), "python:S7505").is_empty());
    }

    #[test]
    fn s7506_prefers_fromkeys_for_constant_values() {
        assert_eq!(
            findings(
                &scan("labels = {k: \"default\" for k in keys}\n"),
                "python:S7506"
            )
            .len(),
            1
        );
        assert!(
            findings(
                &scan("computed = {k: render(k) for k in keys}\n"),
                "python:S7506"
            )
            .is_empty()
        );
    }

    #[test]
    fn s7507_flags_defaultdict_default_factory_keyword() {
        assert_eq!(
            findings(
                &scan("registry = defaultdict(default_factory=list)\n"),
                "python:S7507"
            )
            .len(),
            1
        );
        assert!(findings(&scan("registry = defaultdict(list)\n"), "python:S7507").is_empty());
    }

    #[test]
    fn s7508_flags_nested_identical_constructors() {
        assert_eq!(
            findings(&scan("twice = list(list(rows))\n"), "python:S7508").len(),
            1
        );
        assert!(findings(&scan("mixed = list(set(rows))\n"), "python:S7508").is_empty());
    }

    #[test]
    fn s7510_prefers_reverse_sorting_in_place() {
        assert_eq!(
            findings(
                &scan("descending = reversed(sorted(scores))\n"),
                "python:S7510"
            )
            .len(),
            1
        );
        assert!(
            findings(
                &scan("top = sorted(scores, reverse=True)\n"),
                "python:S7510"
            )
            .is_empty()
        );
    }

    #[test]
    fn s7511_flags_discarded_and_doubled_reversed_calls() {
        let flagged = scan(concat!(
            "lost = set(reversed(stream))\n",
            "kept = sorted(reversed(stream))\n",
            "twice = reversed(reversed(path))\n",
            "meaningful = reversed(sorted(path))\n"
        ));
        let found = findings(&flagged, "python:S7511");
        assert_eq!(found.len(), 3);
        assert_eq!(
            found
                .iter()
                .map(|issue| issue.range.start.line)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn s7516_flags_sorting_before_set_construction() {
        assert_eq!(
            findings(&scan("unique = set(sorted(entries))\n"), "python:S7516").len(),
            1
        );
        assert!(findings(&scan("ordered = list(sorted(entries))\n"), "python:S7516").is_empty());
    }

    #[test]
    fn s7517_flags_manual_key_lookups_by_loop_variable() {
        let flagged = scan("for k in prices:\n    total[k] = prices[k]\n");
        let found = findings(&flagged, "python:S7517");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 2);
        let clean = "for k in prices:\n    show(k)\n";
        assert!(findings(&scan(clean), "python:S7517").is_empty());
    }

    #[test]
    fn s7519_prefers_fromkeys_for_constant_loops() {
        let flagged = scan("flags = {}\nfor name in nodes:\n    flags[name] = True\n");
        let found = findings(&flagged, "python:S7519");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 2);
        let clean = "sizes = {}\nfor name in nodes:\n    sizes[name] = len(name)\n";
        assert!(findings(&scan(clean), "python:S7519").is_empty());
    }

    #[test]
    fn s7512_flags_items_pairs_when_only_keys_used() {
        let flagged = scan("for key, value in record.items():\n    audit(key)\n");
        assert_eq!(findings(&flagged, "python:S7512").len(), 1);
        let clean = "for key, value in record.items():\n    audit(key, value)\n";
        assert!(findings(&scan(clean), "python:S7512").is_empty());
    }
}
