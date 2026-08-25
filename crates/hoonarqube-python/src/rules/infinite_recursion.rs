use crate::support::for_each_stmt;
use crate::support::is_call_to;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_infinite_recursion(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
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
    });
    issues
}

// --- migrated from support/mod.rs (S2190) ---
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
