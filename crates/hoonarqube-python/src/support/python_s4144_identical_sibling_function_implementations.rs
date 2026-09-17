// --- python:S4144 — identical sibling function implementations

use crate::support::{issue_at, suite_span};
use hoonarqube_ir::Issue;
use ruff_python_ast::Stmt;
use ruff_python_ast::token::{Token, TokenKind};
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

/// The reference exempts bodies whose statements fit on one line and bodies
/// that only raise (docstring lines are skipped when measuring).
fn body_is_trivial(body: &[Stmt], index: &LineIndex, source: &str) -> bool {
    let statements: &[Stmt] = match body.first() {
        Some(Stmt::Expr(expr))
            if matches!(expr.value.as_ref(), ruff_python_ast::Expr::StringLiteral(_)) =>
        {
            &body[1..]
        }
        _ => body,
    };
    if statements.is_empty() {
        return true;
    }
    let first_line = index
        .line_column(statements[0].start(), source)
        .line
        .get();
    let last_line = index
        .line_column(statements[statements.len() - 1].end(), source)
        .line
        .get();
    if first_line == last_line {
        return true;
    }
    statements.len() == 1 && matches!(statements[0], Stmt::Raise(_))
}

pub(crate) fn flag_identical_function_pairs(
    suite: &[Stmt],
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
    tokens: &[Token],
) {
    let definitions: Vec<&ruff_python_ast::StmtFunctionDef> = suite
        .iter()
        .filter_map(|stmt| match stmt {
            Stmt::FunctionDef(function) => Some(function),
            _ => None,
        })
        .collect();
    for (position, later) in definitions.iter().enumerate().skip(1) {
        for earlier in &definitions[..position] {
            if body_is_trivial(&earlier.body, index, source)
                || body_is_trivial(&later.body, index, source)
                || !bodies_equal_ignoring_comments(
                    suite_span(&earlier.body),
                    suite_span(&later.body),
                    tokens,
                    source,
                )
            {
                continue;
            }
            issues.push(issue_at(
                "python:S4144",
                &format!(
                    "Refactor this function; it duplicates the implementation of '{}'.",
                    earlier.name.as_str()
                ),
                later.name.range(),
                index,
                source,
            ));
            break;
        }
    }
}

/// Executable-token equality for sibling bodies: trivia (comments, blank
/// lines) and structural newline/indentation tokens carry no behavior, so
/// bodies whose remaining token streams agree are duplicates even when their
/// comments differ (the `PyYAML` `check_key`/`check_value` shape). Comments inside
/// string literals stay `Name`/`String` token content and keep counting.
fn bodies_equal_ignoring_comments(
    left: TextRange,
    right: TextRange,
    tokens: &[Token],
    source: &str,
) -> bool {
    let logical = |range: TextRange| -> Vec<&str> {
        tokens
            .iter()
            .filter(|token| {
                range.contains_range(token.range())
                    && !token.kind().is_trivia()
                    && !matches!(
                        token.kind(),
                        TokenKind::Newline | TokenKind::Indent | TokenKind::Dedent
                    )
            })
            .map(|token| &source[token.range()])
            .collect()
    };
    logical(left) == logical(right)
}
