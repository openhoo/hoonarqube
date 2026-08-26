use crate::engine::calls::LocalSignatures;
use crate::engine::calls::s5655_check_call;
use crate::support::for_each_expr;
use crate::support::for_each_stmt_with_class;
use crate::support::stmt_exprs;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

// --- python:S5655 — arguments should be of an expected type -------------------

/// python:S5655 — flags literal arguments that provably contradict a simple
/// concrete parameter annotation of the resolved file-local callee.
pub(crate) fn check_s5655_argument_kind_mismatches(
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
                s5655_check_call(&resolved, call, &mut issues, index, source);
            });
        }
    });
    issues
}
