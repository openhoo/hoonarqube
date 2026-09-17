use crate::support::child_exprs;
use crate::support::for_each_stmt;
use crate::support::is_dunder_name;
use crate::support::issue_at;
use crate::support::stmt_exprs;
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ModModule, Stmt, StmtFunctionDef};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S2325 — methods that could be static -------------------------------
//
// The reference flags a method only when the class has no inheritance, the
// method is not dunder/static/decorated, the body holds valuable code (more
// than docstring/pass/ellipsis), it never raises NotImplementedError, and the
// first positional parameter is a plain name never used inside the body.

pub(crate) fn check_static_candidates(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::ClassDef(class) = stmt else {
            return;
        };
        // Any base class or `metaclass=` keyword means the method may be an
        // override or metaclass hook; the reference bails out entirely.
        if class
            .arguments
            .as_deref()
            .is_some_and(|arguments| !arguments.args.is_empty() || !arguments.keywords.is_empty())
        {
            return;
        }
        for member in &class.body {
            let Stmt::FunctionDef(function) = member else {
                continue;
            };
            if is_dunder_name(&function.name)
                || !function.decorator_list.is_empty()
                || !has_valuable_code(function)
                || may_raise_not_implemented_error(function)
                || uses_first_parameter(function)
            {
                continue;
            }
            issues.push(issue_at(
                "python:S2325",
                "Make this method static.",
                function.name.range(),
                index,
                source,
            ));
        }
    });
    issues
}

/// Bodies holding only docstrings, `pass`, or `...` carry no behavior worth
/// making static.
fn has_valuable_code(function: &StmtFunctionDef) -> bool {
    function.body.iter().any(|stmt| match stmt {
        Stmt::Pass(_) => false,
        Stmt::Expr(expr) => !matches!(
            expr.value.as_ref(),
            Expr::StringLiteral(_) | Expr::EllipsisLiteral(_)
        ),
        _ => true,
    })
}

/// `raise NotImplementedError` (anywhere, nested raise expressions included)
/// marks the method as an intentional abstract stub.
fn may_raise_not_implemented_error(function: &StmtFunctionDef) -> bool {
    let mut found = false;
    for_each_stmt(function.body.as_slice(), &mut |stmt| {
        if let Stmt::Raise(raise) = stmt {
            for expr in raise.exc.iter().chain(raise.cause.iter()) {
                let mut pending = vec![expr.as_ref()];
                while let Some(expr) = pending.pop() {
                    if matches!(expr, Expr::Name(name) if name.id.as_str() == "NotImplementedError")
                    {
                        found = true;
                    }
                    pending.extend(child_exprs(expr));
                }
            }
        }
    });
    found
}

/// Whether the first parameter is a plain name that the body loads. A
/// variadic or unnamed first parameter cannot be an instance receiver, and a
/// receiver referenced anywhere (nested scopes included) keeps the method
/// instance-bound.
fn uses_first_parameter(function: &StmtFunctionDef) -> bool {
    let parameters = &function.parameters;
    let first = parameters
        .posonlyargs
        .first()
        .or_else(|| parameters.args.first())
        .map(|parameter| &parameter.parameter)
        .or(parameters.vararg.as_deref())
        .or_else(|| parameters.kwonlyargs.first().map(|p| &p.parameter))
        .or(parameters.kwarg.as_deref());
    let Some(first) = first else {
        // No parameters at all: the method cannot use a receiver.
        return false;
    };
    let name = first.name.as_str();
    let mut used = false;
    for_each_stmt(function.body.as_slice(), &mut |stmt| {
        for expr in stmt_exprs(stmt) {
            let mut pending = vec![expr];
            while let Some(expr) = pending.pop() {
                if matches!(expr, Expr::Name(name_expr) if name_expr.id.as_str() == name) {
                    used = true;
                }
                pending.extend(child_exprs(expr));
            }
        }
    });
    used
}
