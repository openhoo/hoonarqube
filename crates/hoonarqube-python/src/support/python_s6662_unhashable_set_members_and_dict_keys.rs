// --- python:S6662 — unhashable set members and dict keys

use crate::support::{
    collect_target_names, for_each_stmt, for_each_stmt_expr, import_binding_name,
};
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use std::collections::HashMap;
use std::collections::HashSet;

/// Fine-grained literal classification (numbers split by numeric type) shared
/// by the Tier-C semantic rules.
pub(crate) fn typed_literal_kind(expr: &Expr) -> Option<&'static str> {
    match expr {
        Expr::NumberLiteral(number) => Some(match &number.value {
            ruff_python_ast::Number::Int(_) => "int",
            ruff_python_ast::Number::Float(_) => "float",
            ruff_python_ast::Number::Complex { .. } => "complex",
        }),
        Expr::StringLiteral(_) => Some("string"),
        Expr::BytesLiteral(_) => Some("bytes"),
        Expr::BooleanLiteral(_) => Some("boolean"),
        Expr::NoneLiteral(_) => Some("none"),
        Expr::List(_) => Some("list"),
        Expr::Tuple(_) => Some("tuple"),
        Expr::Set(_) => Some("set"),
        Expr::Dict(_) => Some("dict"),
        _ => None,
    }
}

/// Names written by a statement: assignment/annotation/augmented targets,
/// deletions, loop and `with` targets, import bindings, definition names,
/// and `global`/`nonlocal` declarations (which license remote writes).
/// Comprehension and match-capture scopes cannot rebind these names.
pub(crate) fn stmt_store_names(stmt: &Stmt) -> Vec<String> {
    let mut names = Vec::new();
    match stmt {
        Stmt::Assign(assign) => {
            for target in &assign.targets {
                collect_target_names(target, &mut names);
            }
        }
        Stmt::AnnAssign(assign) => collect_target_names(&assign.target, &mut names),
        Stmt::AugAssign(assign) => collect_target_names(&assign.target, &mut names),
        Stmt::Delete(delete) => {
            for target in &delete.targets {
                collect_target_names(target, &mut names);
            }
        }
        Stmt::For(loop_stmt) => collect_target_names(&loop_stmt.target, &mut names),
        Stmt::With(with_stmt) => {
            for item in &with_stmt.items {
                if let Some(vars) = item.optional_vars.as_deref() {
                    collect_target_names(vars, &mut names);
                }
            }
        }
        Stmt::Import(import) => {
            for alias in &import.names {
                names.extend(import_binding_name(alias));
            }
        }
        Stmt::ImportFrom(import_from) => {
            for alias in &import_from.names {
                names.extend(import_binding_name(alias));
            }
        }
        Stmt::FunctionDef(function) => names.push(function.name.as_str().to_string()),
        Stmt::ClassDef(class) => names.push(class.name.as_str().to_string()),
        Stmt::Global(global) => {
            for name in &global.names {
                names.push(name.as_str().to_string());
            }
        }
        Stmt::Nonlocal(nonlocal_stmt) => {
            for name in &nonlocal_stmt.names {
                names.push(name.as_str().to_string());
            }
        }
        _ => {}
    }
    names
}

/// Module names provably holding a non-callable literal: assigned a literal
/// exactly once across the whole file by a top-level `name = <literal>`
/// statement. Any second write (loop targets, walrus, `global` declarations,
/// deletion) disqualifies the name.
pub(crate) fn collect_module_literal_bindings(module: &[Stmt]) -> HashSet<String> {
    let mut writes: HashMap<String, usize> = HashMap::new();
    let mut count_writes = |names: Vec<String>| {
        for name in names {
            *writes.entry(name).or_insert(0) += 1;
        }
    };
    for_each_stmt(module, &mut |stmt| {
        count_writes(stmt_store_names(stmt));
        for_each_stmt_expr(std::slice::from_ref(stmt), &mut |expr| {
            if let Expr::Named(named) = expr {
                let mut targets = Vec::new();
                collect_target_names(&named.target, &mut targets);
                count_writes(targets);
            }
        });
    });
    let mut candidates = HashSet::new();
    for stmt in module {
        if let Stmt::Assign(assign) = stmt
            && let [target] = assign.targets.as_slice()
            && let Expr::Name(name) = target
            && typed_literal_kind(&assign.value).is_some()
        {
            candidates.insert(name.id.as_str().to_string());
        }
    }
    candidates.retain(|name| writes.get(name).copied() == Some(1));
    candidates
}
