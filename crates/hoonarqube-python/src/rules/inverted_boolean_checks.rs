use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S1940 — inverted boolean checks ----------------------------------

pub(crate) fn check_inverted_boolean_checks(
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
