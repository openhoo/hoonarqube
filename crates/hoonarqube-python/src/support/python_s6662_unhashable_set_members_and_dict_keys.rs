// --- python:S6662 — unhashable set members and dict keys

use crate::support::{
    collect_target_name_refs, collect_target_names, for_each_stmt, for_each_stmt_expr,
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
    stmt_store_name_refs(stmt)
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// Borrowed-name variant of [`stmt_store_names`]: callers that only need the
/// identifier text avoid one `String` per written name.
pub(crate) fn stmt_store_name_refs(stmt: &Stmt) -> Vec<&str> {
    let mut names = Vec::new();
    match stmt {
        Stmt::Assign(assign) => collect_target_refs(&assign.targets, &mut names),
        Stmt::AnnAssign(assign) => collect_target_name_refs(&assign.target, &mut names),
        Stmt::AugAssign(assign) => collect_target_name_refs(&assign.target, &mut names),
        Stmt::Delete(delete) => collect_target_refs(&delete.targets, &mut names),
        Stmt::For(loop_stmt) => collect_target_name_refs(&loop_stmt.target, &mut names),
        Stmt::With(with_stmt) => with_stmt
            .items
            .iter()
            .filter_map(|item| item.optional_vars.as_deref())
            .for_each(|target| collect_target_name_refs(target, &mut names)),
        Stmt::Import(import) => names.extend(import.names.iter().filter_map(import_binding_ref)),
        Stmt::ImportFrom(import_from) => {
            names.extend(import_from.names.iter().filter_map(import_binding_ref));
        }
        Stmt::FunctionDef(function) => names.push(function.name.as_str()),
        Stmt::ClassDef(class) => names.push(class.name.as_str()),
        Stmt::Global(global) => {
            names.extend(global.names.iter().map(ruff_python_ast::Identifier::as_str));
        }
        Stmt::Nonlocal(nonlocal_stmt) => {
            names.extend(
                nonlocal_stmt
                    .names
                    .iter()
                    .map(ruff_python_ast::Identifier::as_str),
            );
        }
        _ => {}
    }
    names
}

fn collect_target_refs<'a>(targets: &'a [Expr], names: &mut Vec<&'a str>) {
    for target in targets {
        collect_target_name_refs(target, names);
    }
}

/// Borrowed-name variant of [`import_binding_name`]: the local binding an
/// import alias introduces, or `None` for `*`.
fn import_binding_ref(alias: &ruff_python_ast::Alias) -> Option<&str> {
    let name = alias.name.as_str();
    if name == "*" {
        return None;
    }
    Some(match alias.asname.as_deref() {
        Some(asname) => asname,
        None => name.split('.').next().unwrap_or(name),
    })
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
