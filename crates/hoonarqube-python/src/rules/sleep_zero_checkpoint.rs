use crate::support::for_each_expr_in_module;
use crate::support::int_literal_value;
use crate::support::issue_at;
use crate::support::sleep_call_tail;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7491 — sleep(0) instead of a checkpoint ------------------------------

pub(crate) fn check_sleep_zero_checkpoint(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_expr_in_module(parsed.syntax().body.as_slice(), &mut |expr| {
        if let Expr::Await(awaited) = expr
            && let Expr::Call(call) = awaited.value.as_ref()
            && sleep_call_tail(call).is_some()
            && let [only] = &call.arguments.args[..]
            && int_literal_value(only) == Some(0)
        {
            issues.push(issue_at(
                "python:S7491",
                "Replace sleep(0) with a checkpoint call.",
                awaited.range(),
                index,
                source,
            ));
        }
    });
    issues
}
