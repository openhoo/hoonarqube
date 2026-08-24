use crate::support::CANCELLATION_SCOPE_TAILS;
use crate::support::called_name;
use crate::support::for_each_stmt_expr;
use crate::support::for_each_with_in_function_context;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_cancellation_scope_checkpoints(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_with_in_function_context(
        parsed.syntax().body.as_slice(),
        &mut |with_stmt, in_async| {
            if !in_async {
                return;
            }
            let is_scope = with_stmt
                .items
                .iter()
                .any(|item| is_call_context_tail(item, &CANCELLATION_SCOPE_TAILS));
            if is_scope && !suite_contains_checkpoint(&with_stmt.body) {
                issues.push(issue_at(
                    "python:S7490",
                    "Add a checkpoint (an await point) inside this cancellation scope.",
                    with_stmt.range(),
                    index,
                    source,
                ));
            }
        },
    );
    issues
}

// --- migrated from support/mod.rs (S7490) ---
// --- python:S7490 / python:S7497 — cancellation contracts -----------------------

pub(crate) fn suite_contains_checkpoint(suite: &[Stmt]) -> bool {
    let mut found = false;
    for_each_stmt_expr(suite, &mut |expr| {
        found |= matches!(expr, Expr::Await(_));
    });
    found
}

pub(crate) fn is_call_context_tail(item: &ruff_python_ast::WithItem, tails: &[&str]) -> bool {
    let Expr::Call(call) = &item.context_expr else {
        return false;
    };
    called_name(&call.func).is_some_and(|tail| tails.contains(&tail))
}
