use crate::support::PURE_FREE_FUNCTIONS;
use crate::support::PURE_STRING_METHODS;
use crate::support::called_name;
use crate::support::for_each_stmt;
use crate::support::is_pure_string_expression;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

/// python:S2201 — bare-statement calls whose result is provably pure (the
/// static free-function allowlist, or a pure-`str`-method chain rooted at a
/// string literal) discard their return value.
pub(crate) fn check_s2201_ignored_pure_returns(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::Expr(expr_stmt) = stmt else {
            return;
        };
        let Expr::Call(call) = expr_stmt.value.as_ref() else {
            return;
        };
        let discarded = match call.func.as_ref() {
            Expr::Name(name) => PURE_FREE_FUNCTIONS.contains(&name.id.as_str()),
            Expr::Attribute(attribute) => {
                PURE_STRING_METHODS.contains(&attribute.attr.as_str())
                    && is_pure_string_expression(&attribute.value)
            }
            _ => false,
        };
        if !discarded {
            return;
        }
        issues.push(issue_at(
            "python:S2201",
            &format!(
                "The return value of '{}' is not used.",
                called_name(&call.func).unwrap_or_default()
            ),
            call.range(),
            index,
            source,
        ));
    });
    issues
}
