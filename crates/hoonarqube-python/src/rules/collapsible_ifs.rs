use crate::support::child_bodies;
use crate::support::to_range;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_ast::StmtIf;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use ruff_text_size::{TextRange, TextSize};

// --- python:S1066 — collapsible nested ifs -----------------------------------

pub(crate) fn check_collapsible_ifs(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    visit_suite(
        parsed.syntax().body.as_slice(),
        parsed,
        &mut issues,
        index,
        source,
    );
    issues
}

/// Walrus conditions cannot merge into `and` without changing evaluation.
fn contains_walrus(expr: &ruff_python_ast::Expr) -> bool {
    let mut pending = vec![expr];
    while let Some(expr) = pending.pop() {
        if matches!(expr, ruff_python_ast::Expr::Named(_)) {
            return true;
        }
        pending.extend(crate::support::child_exprs(expr));
    }
    false
}

/// Comments between the enclosing `if` and the inner `if` (or trailing the
/// enclosing header) exempt the merge.
fn has_comment_before_inner(
    inner: &StmtIf,
    outer: &StmtIf,
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> bool {
    let _ = parsed;
    let inner_line = index.line_column(inner.start(), source).line.get();
    parsed.tokens().iter().any(|token| {
        token.kind() == ruff_python_ast::token::TokenKind::Comment
            && token.range().start() >= outer.range().start()
            && index.line_column(token.range().start(), source).line.get() < inner_line
    })
}

/// Merging `outer` and `inner` conditions with ` and ` must stay within 80
/// columns.
fn merged_line_too_long(
    inner: &StmtIf,
    outer: &StmtIf,
    index: &LineIndex,
    source: &str,
) -> bool {
    let outer_end = index.line_column(outer.test.end(), source);
    let inner_start = index.line_column(inner.test.start(), source);
    let inner_end = index.line_column(inner.test.end(), source);
    let outer_last_column = outer_end.column.get() as usize;
    let inner_condition_length = inner_end.column.get() as usize
        - inner_start.column.get() as usize;
    outer_last_column + inner_condition_length + 5 > 80
}

fn visit_suite(
    suite: &[Stmt],
    parsed: &Parsed<ModModule>,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    for stmt in suite {
        if let Stmt::If(outer) = stmt {
            collapsible_inner(outer, parsed, issues, index, source);
        }
        for body in child_bodies(stmt) {
            visit_suite(body, parsed, issues, index, source);
        }
    }
}

/// An `if` whose then-suite holds exactly one further `if`, where neither
/// carries elif/else clauses, merges into a single condition joined by `and`.
/// The same merge applies to an `elif` suite whose sole statement is a
/// clause-free `if` (`elif a: if b:` becomes `elif a and b:`). Clauses with
/// `elif`/`else` (including an `else` suite holding one lone `if`, which
/// would flatten into a new `elif`) change semantics and are exempt.
fn collapsible_inner(
    outer: &StmtIf,
    parsed: &Parsed<ModModule>,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    if outer.elif_else_clauses.is_empty()
        && let [Stmt::If(inner)] = outer.body.as_slice()
    {
        push_collapsible(inner, outer, parsed, issues, index, source);
    }
    // The reference ignores `elif` branches except the last one when the
    // chain has no `else`: only that final elif can merge upward.
    let has_else = outer
        .elif_else_clauses
        .last()
        .is_some_and(|clause| clause.test.is_none());
    let last_tested = outer
        .elif_else_clauses
        .iter()
        .rposition(|clause| clause.test.is_some());
    if let Some(last) = last_tested.filter(|_| !has_else)
        && let [Stmt::If(inner)] = outer.elif_else_clauses[last].body.as_slice()
    {
        push_collapsible(inner, outer, parsed, issues, index, source);
    }
}

fn push_collapsible(
    inner: &StmtIf,
    outer: &StmtIf,
    parsed: &Parsed<ModModule>,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    if !inner.elif_else_clauses.is_empty()
        || contains_walrus(&inner.test)
        || contains_walrus(&outer.test)
        || has_comment_before_inner(inner, outer, parsed, index, source)
        || merged_line_too_long(inner, outer, index, source)
    {
        return;
    }
    issues.push(Issue::new(
        "python:S1066",
        "Merge this if statement with the enclosing one.",
        to_range(
            TextRange::new(inner.start(), inner.start() + TextSize::new(2)),
            index,
            source,
        ),
    ));
}
