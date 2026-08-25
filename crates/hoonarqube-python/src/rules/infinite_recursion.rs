use crate::engine::file_context::FileContext;
use crate::support::is_call_to;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_infinite_recursion(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        if let Stmt::FunctionDef(function) = stmt
            && straight_line_self_call(&function.body, function.name.as_str())
        {
            issues.push(issue_at(
                "python:S2190",
                "Add a way to break out of this recursive call.",
                function.name.range(),
                index,
                source,
            ));
        }
    }
    issues
}

// --- python:S2190 — infinite recursion ---------------------------------------

fn straight_line_self_call(suite: &[Stmt], name: &str) -> bool {
    for stmt in suite {
        match stmt {
            Stmt::Expr(expr_stmt) => {
                if is_call_to(&expr_stmt.value, name) {
                    return true;
                }
            }
            Stmt::Return(return_stmt) => {
                if let Some(value) = return_stmt.value.as_deref()
                    && is_call_to(value, name)
                {
                    return true;
                }
            }
            _ => return false,
        }
    }
    false
}
