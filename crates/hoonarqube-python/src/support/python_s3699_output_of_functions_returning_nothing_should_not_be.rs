// --- python:S3699 — output of functions returning nothing should not be used -

use crate::support::child_bodies;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;

/// Visits `return` statements of a suite without descending into nested
/// function or class definitions.
pub(crate) fn for_each_return_in_scope(
    suite: &[Stmt],
    visit: &mut impl FnMut(&ruff_python_ast::StmtReturn),
) {
    let mut pending: Vec<&Stmt> = suite.iter().rev().collect();
    while let Some(stmt) = pending.pop() {
        match stmt {
            Stmt::Return(returned) => visit(returned),
            Stmt::FunctionDef(_) | Stmt::ClassDef(_) => {}
            other => {
                for body in child_bodies(other).into_iter().rev() {
                    pending.extend(body.iter().rev());
                }
            }
        }
    }
}

/// Direct base-class names of a class declaration (plain names only).
pub(crate) fn direct_base_names(class: &ruff_python_ast::StmtClassDef) -> Vec<&str> {
    match class.arguments.as_deref() {
        Some(arguments) => arguments
            .args
            .iter()
            .filter_map(|base| match base {
                Expr::Name(name) => Some(name.id.as_str()),
                _ => None,
            })
            .collect(),
        None => Vec::new(),
    }
}

/// Depth-first statement walk tracking the innermost file-local class name so
/// `self.`/`cls.` callees can be resolved.
pub(crate) fn for_each_stmt_with_class<'a>(
    stmts: &'a [Stmt],
    class: Option<&'a str>,
    visit: &mut impl FnMut(&'a Stmt, Option<&'a str>),
) {
    let mut pending: Vec<(&Stmt, Option<&str>)> =
        stmts.iter().rev().map(|stmt| (stmt, class)).collect();
    while let Some((stmt, class)) = pending.pop() {
        visit(stmt, class);
        let nested_class = match stmt {
            Stmt::ClassDef(nested) => Some(nested.name.as_str()),
            _ => class,
        };
        for body in child_bodies(stmt).into_iter().rev() {
            pending.extend(body.iter().rev().map(|child| (child, nested_class)));
        }
    }
}
