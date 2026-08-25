use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::for_each_expr;
use crate::support::for_each_stmt_in_scope;
use crate::support::function_parameters;
use crate::support::is_none_literal;
use crate::support::issue_at;
use crate::support::stmt_exprs;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_mutable_default_mutation(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let _ = source;
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        if let Stmt::FunctionDef(function) = stmt {
            for parameter in function_parameters(function) {
                let Some(default) = parameter.default() else {
                    continue;
                };
                if is_mutable_default(default)
                    && parameter_is_mutated(&function.body, parameter.parameter.name.as_str())
                {
                    issues.push(issue_at(
                        "python:S5717",
                        "Do not mutate this mutable default argument.",
                        default.range(),
                        index,
                        source,
                    ));
                }
                if !is_none_literal(default)
                    && parameter_is_assigned(&function.body, parameter.parameter.name.as_str())
                {
                    issues.push(issue_at(
                        "python:S5717",
                        "Do not assign to this parameter; introduce a local variable.",
                        default.range(),
                        index,
                        source,
                    ));
                }
            }
        }
    }
    issues
}

// --- python:S5717 — modified/assigned parameters ----------------------------------------

const MUTATING_METHODS: [&str; 9] = [
    "append",
    "extend",
    "insert",
    "remove",
    "pop",
    "clear",
    "update",
    "add",
    "setdefault",
];

fn is_mutable_default(expr: &Expr) -> bool {
    matches!(expr, Expr::List(_) | Expr::Dict(_) | Expr::Set(_)) || called_name_of_constructor(expr)
}

fn called_name_of_constructor(expr: &Expr) -> bool {
    matches!(expr, Expr::Call(call)
        if matches!(called_name(&call.func), Some("list" | "dict" | "set"))
            && call.arguments.args.is_empty()
            && call.arguments.keywords.is_empty())
}

fn parameter_is_assigned(body: &[Stmt], name: &str) -> bool {
    let mut assigned = false;
    for_each_stmt_in_scope(body, &mut |stmt| {
        if let Stmt::Assign(assign) = stmt {
            for target in &assign.targets {
                assigned |= matches!(target, Expr::Name(name_target)
                    if name_target.id.as_str() == name);
            }
        }
    });
    assigned
}

fn parameter_is_mutated(body: &[Stmt], name: &str) -> bool {
    let mut mutated = false;
    for_each_stmt_in_scope(body, &mut |stmt| {
        match stmt {
            Stmt::AugAssign(aug) => {
                mutated |= matches!(aug.target.as_ref(), Expr::Name(n) if n.id.as_str() == name);
            }
            Stmt::Assign(assign) => {
                for target in &assign.targets {
                    mutated |= matches!(target, Expr::Subscript(subscript)
                        if matches!(subscript.value.as_ref(), Expr::Name(n) if n.id.as_str() == name));
                }
            }
            _ => {}
        }
        for expr in stmt_exprs(stmt) {
            for_each_expr(expr, &mut |expr| {
                if let Expr::Call(call) = expr
                    && let Expr::Attribute(attribute) = call.func.as_ref()
                    && matches!(attribute.value.as_ref(), Expr::Name(n) if n.id.as_str() == name)
                    && MUTATING_METHODS.contains(&attribute.attr.as_str())
                {
                    mutated = true;
                }
            });
        }
    });
    mutated
}
