use crate::support::flag_copy_only;
use crate::support::for_each_stmt_expr;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7500 — copy-only comprehensions -----------------------------------

pub(crate) fn check_copy_only_comprehensions(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| match expr {
        Expr::ListComp(comp) => flag_copy_only(
            comp.elt.as_ref(),
            &comp.generators,
            comp.range(),
            &mut issues,
            index,
            source,
        ),
        Expr::SetComp(comp) => flag_copy_only(
            comp.elt.as_ref(),
            &comp.generators,
            comp.range(),
            &mut issues,
            index,
            source,
        ),
        _ => {}
    });
    issues
}
