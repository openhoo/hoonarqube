use crate::support::for_each_expr;
use crate::support::for_each_stmt;
use crate::support::for_each_stmt_in_scope;
use crate::support::is_none_literal;
use crate::support::issue_at;
use crate::support::stmt_exprs;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S2712 — return with a value in a generator -------------------------

pub(crate) fn check_generator_return_values(
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
