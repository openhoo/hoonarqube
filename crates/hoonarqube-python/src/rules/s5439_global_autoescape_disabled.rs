use crate::support::autoescape_off;
use crate::support::for_each_expr;
use crate::support::for_each_stmt_in_scope;
use crate::support::issue_at;
use crate::support::stmt_exprs;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

/// Module/global scope only: `Environment(autoescape=False)` at import scope.
pub(crate) fn check_s5439_global_autoescape_disabled(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_in_scope(parsed.syntax().body.as_slice(), &mut |stmt| {
        for expr in stmt_exprs(stmt) {
            for_each_expr(expr, &mut |candidate| {
                if let Expr::Call(call) = candidate
                    && autoescape_off(call)
                {
                    issues.push(issue_at(
                        "python:S5439",
                        "Enable auto-escaping globally in this template engine environment.",
                        call.range(),
                        index,
                        source,
                    ));
                }
            });
        }
    });
    issues
}
