// --- Typing-syntax rules (#168–#178).

use crate::support::{called_name, for_each_stmt, function_parameters, unmasked_segments};
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

/// Whether raw (unmasked) source declares PEP 695 `type X = ...` aliases.
pub(crate) fn pep695_aliases_present(parsed: &Parsed<ModModule>, source: &str) -> bool {
    unmasked_segments(parsed, source)
        .iter()
        .any(|(_, segment)| {
            segment.lines().any(|line| {
                let trimmed = line.trim_start();
                trimmed.starts_with("type ") && trimmed.contains('=')
            })
        })
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
