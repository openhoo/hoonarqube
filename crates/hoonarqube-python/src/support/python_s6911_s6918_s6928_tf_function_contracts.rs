// --- python:S6911 / S6918 / S6928 — tf.function contracts

use crate::support::{child_bodies, for_each_stmt, is_tf_function};
use ruff_python_ast::Stmt;

pub(crate) fn for_each_tf_function_body(
    module_body: &[Stmt],
    visit: &mut impl FnMut(&ruff_python_ast::StmtFunctionDef),
) {
    for_each_stmt(module_body, &mut |stmt| {
        if let Stmt::FunctionDef(function) = stmt
            && is_tf_function(function)
        {
            visit(function);
        }
    });
}

pub(crate) fn for_each_with_in_function_context(
    module_body: &[Stmt],
    visit: &mut impl FnMut(&ruff_python_ast::StmtWith, bool),
) {
    fn walk(
        suite: &[Stmt],
        in_async: bool,
        visit: &mut impl FnMut(&ruff_python_ast::StmtWith, bool),
    ) {
        for stmt in suite {
            match stmt {
                Stmt::FunctionDef(function) => walk(&function.body, function.is_async, visit),
                Stmt::ClassDef(class) => walk(&class.body, false, visit),
                Stmt::With(with_stmt) => {
                    visit(with_stmt, in_async);
                    walk(&with_stmt.body, in_async, visit);
                }
                _ => {
                    for body in child_bodies(stmt) {
                        walk(body, in_async, visit);
                    }
                }
            }
        }
    }
    walk(module_body, false, visit);
}
