// --- Typing-syntax rules (#168–#178).

use crate::support::{called_name, for_each_stmt, function_parameters};
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;

/// Visits every annotation expression in the tree: parameter annotations,
/// return annotations, and annotated assignments.
pub(crate) fn for_each_annotation(module_body: &[Stmt], visit: &mut impl FnMut(&Expr)) {
    for_each_stmt(module_body, &mut |stmt| match stmt {
        Stmt::FunctionDef(function) => {
            for parameter in function_parameters(function) {
                if let Some(annotation) = &parameter.parameter.annotation {
                    visit(annotation);
                }
            }
            if let Some(returns) = &function.returns {
                visit(returns);
            }
        }
        Stmt::AnnAssign(assign) => visit(&assign.annotation),
        _ => {}
    });
}

/// Whether the syntax tree declares PEP 695 `type X = ...` aliases.
///
/// Detection is syntax-aware: an ordinary assignment to a variable named
/// `type` (`type = "file"`) binds a plain name, not an alias declaration,
/// so it must not enable the PEP 695 gates. Every real `Stmt::TypeAlias`,
/// including declarations nested in functions or classes, activates them.
pub(crate) fn pep695_aliases_present(parsed: &Parsed<ModModule>) -> bool {
    let mut present = false;
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if matches!(stmt, Stmt::TypeAlias(_)) {
            present = true;
        }
    });
    present
}

/// Names bound by `X = TypeVar(...)` assignments anywhere in the tree.
pub(crate) fn collect_typevar_names(module_body: &[Stmt]) -> Vec<String> {
    let mut names = Vec::new();
    for_each_stmt(module_body, &mut |stmt| {
        if let Stmt::Assign(assign) = stmt
            && let [Expr::Name(target)] = assign.targets.as_slice()
            && let Expr::Call(call) = assign.value.as_ref()
            && called_name(&call.func) == Some("TypeVar")
        {
            names.push(target.id.to_string());
        }
    });
    names
}
