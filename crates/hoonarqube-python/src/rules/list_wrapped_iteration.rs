use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7504 — list() when iterating ---------------------------------------

pub(crate) fn check_list_wrapped_iteration(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        if let Stmt::For(for_stmt) = stmt
            && let Expr::Call(call) = for_stmt.iter.as_ref()
            // Only the bare `list(...)` builtin — `finder.list(...)` is a
            // method call, not a cast.
            && matches!(call.func.as_ref(), Expr::Name(name) if name.id.as_str() == "list")
            && !collection_mutated_in_loop(for_stmt, call)
        {
            issues.push(issue_at(
                "python:S7504",
                "Iterate over the iterable directly; wrapping it in 'list()' is unnecessary.",
                for_stmt.iter.range(),
                index,
                source,
            ));
        }
    }
    issues
}

/// Sonar exempts `list(x.items())`/`keys()`/`values()` when `x` is mutated
/// inside the loop — the copy is intentional.
fn collection_mutated_in_loop(
    for_stmt: &ruff_python_ast::StmtFor,
    call: &ruff_python_ast::ExprCall,
) -> bool {
    let Some(arg) = call.arguments.args.first() else {
        return false;
    };
    let Expr::Call(view) = arg else {
        return false;
    };
    let Expr::Attribute(view_attr) = view.func.as_ref() else {
        return false;
    };
    if !matches!(view_attr.attr.as_str(), "items" | "keys" | "values") {
        return false;
    }
    let Expr::Name(collection) = view_attr.value.as_ref() else {
        return false;
    };
    let mut mutated = false;
    crate::support::for_each_stmt(&for_stmt.body, &mut |stmt| {
        match stmt {
            // `del x[k]` or `x[k] = v` mutates the collection.
            Stmt::Delete(del) => {
                for target in &del.targets {
                    if let Expr::Subscript(sub) = target
                        && matches!(sub.value.as_ref(), Expr::Name(n) if n.id == collection.id)
                    {
                        mutated = true;
                    }
                }
            }
            Stmt::Assign(assign) => {
                for target in &assign.targets {
                    if let Expr::Subscript(sub) = target
                        && matches!(sub.value.as_ref(), Expr::Name(n) if n.id == collection.id)
                    {
                        mutated = true;
                    }
                }
            }
            _ => {}
        }
        // `x.pop(...)`, `x.update(...)`, `x.clear()`, `x.setdefault(...)`,
        // `x.popitem()` mutate the collection.
        crate::support::for_each_stmt_expr(std::slice::from_ref(stmt), &mut |expr| {
            if let Expr::Call(call) = expr
                && let Expr::Attribute(attr) = call.func.as_ref()
                && matches!(
                    attr.attr.as_str(),
                    "pop"
                        | "popitem"
                        | "clear"
                        | "update"
                        | "setdefault"
                        | "append"
                        | "extend"
                        | "insert"
                        | "remove"
                        | "sort"
                        | "reverse"
                )
                && matches!(attr.value.as_ref(), Expr::Name(n) if n.id == collection.id)
            {
                mutated = true;
            }
        });
    });
    mutated
}
