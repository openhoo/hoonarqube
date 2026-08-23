use crate::support::NON_ITERATOR_RETURNS;
use crate::support::for_each_return_in_scope;
use crate::support::for_each_stmt;
use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
use crate::support::typed_literal_kind;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

/// python:S2876 — flags `__iter__` bodies (of file-local classes) returning
/// collection literals or known non-iterator calls. Generator bodies and
/// `return self` / `iter(...)` shapes pass by construction.
pub(crate) fn check_s2876_iter_returns(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::ClassDef(class) = stmt else {
            return;
        };
        let Some(function) = class.body.iter().find_map(|member| match member {
            Stmt::FunctionDef(function) if function.name.as_str() == "__iter__" => Some(function),
            _ => None,
        }) else {
            return;
        };
        let mut yields = false;
        for_each_stmt_expr(&function.body, &mut |expr| {
            if matches!(expr, Expr::Yield(_) | Expr::YieldFrom(_)) {
                yields = true;
            }
        });
        if yields {
            return;
        }
        for_each_return_in_scope(&function.body, &mut |returned| {
            let Some(value) = returned.value.as_deref() else {
                return;
            };
            let not_iterator = typed_literal_kind(value).is_some()
                || matches!(value, Expr::Call(call)
                    if matches!(call.func.as_ref(), Expr::Name(name)
                        if NON_ITERATOR_RETURNS.contains(&name.id.as_str())));
            if !not_iterator {
                return;
            }
            issues.push(issue_at(
                "python:S2876",
                "__iter__ should return an iterator object.",
                value.range(),
                index,
                source,
            ));
        });
    });
    issues
}
