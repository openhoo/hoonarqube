use crate::support::called_name;
use crate::support::for_each_stmt_expr;
use crate::support::for_each_tf_function_body;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_tf_variable_creation(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_tf_function_body(parsed.syntax().body.as_slice(), &mut |function| {
        for_each_stmt_expr(&function.body, &mut |expr| {
            if let Expr::Call(call) = expr
                && called_name(&call.func) == Some("Variable")
            {
                issues.push(issue_at(
                    "python:S6918",
                    "Create this tf.Variable outside the traced function; it would be recreated on each tracing run.",
                    call.range(),
                    index,
                    source,
                ));
            }
        });
    });
    issues
}
