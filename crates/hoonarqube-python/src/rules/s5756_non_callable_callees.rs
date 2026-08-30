use crate::support::collect_module_literal_bindings;
use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
use crate::support::typed_literal_kind;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5756 — calls should not be made to non-callable values ----------

/// Flags calls whose callee is a literal, or a module name proven by
/// [`collect_module_literal_bindings`] to hold a non-callable literal.
pub(crate) fn check_s5756_non_callable_callees(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let module = parsed.syntax().body.as_slice();
    let bindings = collect_module_literal_bindings(module);
    let mut issues = Vec::new();
    for_each_stmt_expr(module, &mut |expr| {
        let Expr::Call(call) = expr else {
            return;
        };
        if let Some(kind) = typed_literal_kind(&call.func) {
            let type_name = match kind {
                "string" => "str",
                "boolean" => "bool",
                "none" => "None",
                other => other,
            };
            issues.push(issue_at(
                "python:S5756",
                &format!(
                    "Fix this call; this expression has type {type_name} and it is not callable."
                ),
                call.func.range(),
                index,
                source,
            ));
            return;
        }
        if let Expr::Name(name) = call.func.as_ref()
            && bindings.contains(name.id.as_str())
        {
            issues.push(issue_at(
                "python:S5756",
                &format!("'{}' is not callable.", name.id.as_str()),
                call.func.range(),
                index,
                source,
            ));
        }
    });
    issues
}
