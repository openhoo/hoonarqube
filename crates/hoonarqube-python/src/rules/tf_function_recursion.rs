use crate::support::called_name;
use crate::support::for_each_stmt;
use crate::support::for_each_stmt_expr;
use crate::support::is_tf_function;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6908 — recursion inside tf.function ------------------------------

pub(crate) fn check_tf_function_recursion(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::FunctionDef(function) = stmt else {
            return;
        };
        if !is_tf_function(function) {
            return;
        }
        let mut flagged = false;
        for_each_stmt_expr(&function.body, &mut |expr| {
            if !flagged
                && let Expr::Call(call) = expr
                && called_name(&call.func) == Some(function.name.as_str())
            {
                flagged = true;
                issues.push(issue_at(
                    "python:S6908",
                    "Rewrite this recursion; it is not supported inside a tf.function.",
                    call.range(),
                    index,
                    source,
                ));
            }
        });
    });
    issues
}
