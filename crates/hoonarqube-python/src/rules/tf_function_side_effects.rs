use crate::support::SIDE_EFFECT_TAILS;
use crate::support::called_name;
use crate::support::for_each_stmt_expr;
use crate::support::for_each_stmt_in_scope;
use crate::support::for_each_tf_function_body;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_tf_function_side_effects(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_tf_function_body(parsed.syntax().body.as_slice(), &mut |function| {
        for_each_stmt_expr(&function.body, &mut |expr| {
            if let Expr::Call(call) = expr
                && called_name(&call.func).is_some_and(|tail| SIDE_EFFECT_TAILS.contains(&tail))
            {
                issues.push(issue_at(
                    "python:S6928",
                    "Move this Python side effect out of the tf.function; it runs only once during tracing.",
                    call.range(),
                    index,
                    source,
                ));
            }
        });
        for_each_stmt_in_scope(&function.body, &mut |stmt| {
            if let Stmt::Assert(assert_stmt) = stmt {
                issues.push(issue_at(
                    "python:S6928",
                    "Move this Python side effect out of the tf.function; it runs only once during tracing.",
                    assert_stmt.range(),
                    index,
                    source,
                ));
            }
        });
    });
    issues
}
