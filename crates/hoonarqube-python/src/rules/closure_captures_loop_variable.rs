use crate::support::collect_target_names;
use crate::support::for_each_stmt;
use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
use crate::support::loads_any_name;
use crate::support::stmts_load_any_name;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S1515 — closures capturing loop variables --------------------------

pub(crate) fn check_closure_captures_loop_variable(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::For(for_stmt) = stmt else { return };
        let mut targets = Vec::new();
        collect_target_names(&for_stmt.target, &mut targets);
        if targets.is_empty() {
            return;
        }
        for_each_stmt_expr(&for_stmt.body, &mut |expr| {
            if let Expr::Lambda(lambda) = expr
                && loads_any_name(&lambda.body, &targets)
            {
                issues.push(issue_at(
                    "python:S1515",
                    "This closure captures a loop variable by reference; bind it with a default argument.",
                    lambda.range(),
                    index,
                    source,
                ));
            }
        });
        for_each_stmt(&for_stmt.body, &mut |nested| {
            if let Stmt::FunctionDef(function) = nested
                && stmts_load_any_name(&function.body, &targets)
            {
                issues.push(issue_at(
                    "python:S1515",
                    "This closure captures a loop variable by reference; bind it with a default argument.",
                    function.name.range(),
                    index,
                    source,
                ));
            }
        });
    });
    issues
}
