use crate::engine::calls::LocalSignatures;
use crate::engine::calls::s930_arity_problem;
use crate::support::called_name;
use crate::support::for_each_expr;
use crate::support::for_each_stmt_with_class;
use crate::support::issue_at;
use crate::support::stmt_exprs;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

/// python:S930 — flags arity mismatches of calls resolvable against the
/// file-local tables ([`LocalSignatures`]): module functions, constructors,
/// `self`/`cls` methods, uniquely-bound instances, and class accesses.
pub(crate) fn check_s930_arity_mismatches(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    signatures: &LocalSignatures,
) -> Vec<Issue> {
    let module = parsed.syntax().body.as_slice();
    let mut issues = Vec::new();
    for_each_stmt_with_class(module, None, &mut |stmt, class_context| {
        for top_expr in stmt_exprs(stmt) {
            for_each_expr(top_expr, &mut |expr| {
                let Expr::Call(call) = expr else {
                    return;
                };
                let Some(resolved) = signatures.resolve(&call.func, class_context) else {
                    return;
                };
                let Some(problem) = s930_arity_problem(&resolved, &call.arguments) else {
                    return;
                };
                let label = called_name(&call.func).unwrap_or_default();
                issues.push(issue_at(
                    "python:S930",
                    &format!("The call to '{label}' passes {problem}."),
                    call.range(),
                    index,
                    source,
                ));
            });
        }
    });
    issues
}

// --- python:S930 — call arguments should match parameters ----------------------
