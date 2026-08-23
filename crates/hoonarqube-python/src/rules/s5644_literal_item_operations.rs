use crate::support::for_each_stmt_expr;
use crate::support::is_non_supporting_kind;
use crate::support::issue_at;
use crate::support::literal_kind;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5644 — item operations on literals -----------------------------------

pub(crate) fn check_s5644_literal_item_operations(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        if let Expr::Subscript(subscript) = expr
            && literal_kind(subscript.value.as_ref()).is_some_and(is_non_supporting_kind)
        {
            issues.push(issue_at(
                "python:S5644",
                "This value does not support item access.",
                expr.range(),
                index,
                source,
            ));
        }
    });
    issues
}
