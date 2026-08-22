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
}
