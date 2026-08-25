// --- python:S5719 — instance/class methods need a positional parameter

use crate::support::for_each_stmt;
use ruff_python_ast::Stmt;

/// Iterates `(class, function)` for every method directly defined in a class
/// body anywhere in the tree.
pub(crate) fn for_each_method(
    stmts: &[Stmt],
    visit: &mut impl FnMut(&ruff_python_ast::StmtClassDef, &ruff_python_ast::StmtFunctionDef),
) {
    for_each_stmt(stmts, &mut |stmt| {
        if let Stmt::ClassDef(class) = stmt {
            for member in &class.body {
                if let Stmt::FunctionDef(function) = member {
                    visit(class, function);
                }
            }
        }
    });
}
