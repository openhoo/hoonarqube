use crate::support::child_bodies;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_ast::StmtIf;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S1066 — collapsible nested ifs -----------------------------------

pub(crate) fn check_collapsible_ifs(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    visit_suite(parsed.syntax().body.as_slice(), &mut issues, index, source);
    issues
}

fn visit_suite(suite: &[Stmt], issues: &mut Vec<Issue>, index: &LineIndex, source: &str) {
    for stmt in suite {
        if let Stmt::If(outer) = stmt {
            collapsible_inner(outer, issues, index, source);
        }
        for body in child_bodies(stmt) {
            visit_suite(body, issues, index, source);
        }
    }
}

/// An `if` whose then-suite holds exactly one further `if`, where neither
/// carries elif/else clauses, merges into a single condition joined by `and`.
/// Clauses with `elif`/`else` (including an `else` suite holding one lone `if`)
/// change semantics when flattened and are exempt.
fn collapsible_inner(outer: &StmtIf, issues: &mut Vec<Issue>, index: &LineIndex, source: &str) {
    if !outer.elif_else_clauses.is_empty() {
        return;
    }
    let [Stmt::If(inner)] = outer.body.as_slice() else {
        return;
    };
    if !inner.elif_else_clauses.is_empty() {
        return;
    }
    issues.push(issue_at(
        "python:S1066",
        "Merge this if statement with the enclosing one.",
        inner.range(),
        index,
        source,
    ));
}
