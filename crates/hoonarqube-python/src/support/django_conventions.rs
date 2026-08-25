// --- Django conventions

use crate::context::context_is_async;
use crate::context::for_each_call_in_fn_context;
use crate::support::{called_name, dotted_name, issue_at};
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) const DJANGO_STRING_FIELDS: [&str; 4] =
    ["CharField", "TextField", "SlugField", "EmailField"];

pub(crate) fn class_defines_method(class: &ruff_python_ast::StmtClassDef, name: &str) -> bool {
    class
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::FunctionDef(function) if function.name.as_str() == name))
}

pub(crate) fn is_locals_call(expr: &Expr) -> bool {
    matches!(expr, Expr::Call(call) if called_name(&call.func) == Some("locals"))
}

pub(crate) fn meta_declares_fields(meta: &ruff_python_ast::StmtClassDef) -> bool {
    meta.body.iter().any(|stmt| {
        let target_name = match stmt {
            Stmt::Assign(assign) => assign.targets.first().and_then(|target| match target {
                Expr::Name(name) => Some(name.id.as_str().to_string()),
                _ => None,
            }),
            Stmt::AnnAssign(assign) => match assign.target.as_ref() {
                Expr::Name(name) => Some(name.id.as_str().to_string()),
                _ => None,
            },
            _ => None,
        };
        matches!(target_name.as_deref(), Some("fields" | "exclude"))
    })
}

pub(crate) const ROUTE_DECORATOR_TAILS: [&str; 9] = [
    "route", "get", "post", "put", "patch", "delete", "head", "options", "receiver",
];

/// Callee path of a decorator expression (`app.route` for `@app.route("/")`).
pub(crate) fn decorator_callee_path(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Call(call) => dotted_name(&call.func),
        _ => dotted_name(expr),
    }
}

pub(crate) fn assignment_target_leaf_name(target: &Expr) -> Option<String> {
    match target {
        Expr::Name(name) => Some(name.id.as_str().to_string()),
        Expr::Attribute(attribute) => Some(attribute.attr.as_str().to_string()),
        _ => None,
    }
}

pub(crate) fn sleep_call_tail(call: &ruff_python_ast::ExprCall) -> Option<String> {
    dotted_name(&call.func)
        .and_then(|path| path.rsplit('.').next().map(str::to_string))
        .filter(|tail| tail == "sleep")
}

pub(crate) fn flag_sync_calls_inside_async(
    module_body: &[Stmt],
    accepted: &impl Fn(&ruff_python_ast::ExprCall) -> bool,
    rule_key: &str,
    message: &str,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    for_each_call_in_fn_context(module_body, &mut |call, ctx| {
        if context_is_async(ctx) && accepted(call) {
            issues.push(issue_at(rule_key, message, call.range(), index, source));
        }
    });
}

pub(crate) fn function_parameters(
    function: &ruff_python_ast::StmtFunctionDef,
) -> Vec<&ruff_python_ast::ParameterWithDefault> {
    let parameters = &function.parameters;
    parameters
        .posonlyargs
        .iter()
        .chain(parameters.args.iter())
        .chain(parameters.kwonlyargs.iter())
        .collect()
}
