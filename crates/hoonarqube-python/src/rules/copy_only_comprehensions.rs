use crate::support::flag_copy_only;
use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ModModule};
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
        Expr::Generator(comp) => {
            let [generator] = comp.generators.as_slice() else {
                return;
            };
            if !generator.ifs.is_empty()
                || generator.is_async
                || !same_name(comp.elt.as_ref(), &generator.target)
            {
                return;
            }
            issues.push(issue_at(
                "python:S7500",
                "Copy the iterable directly instead of using a comprehension that only renames.",
                comp.range(),
                index,
                source,
            ));
        }
        Expr::DictComp(comp) => {
            let [generator] = comp.generators.as_slice() else {
                return;
            };
            let Some(key) = comp.key.as_deref() else {
                return;
            };
            let Expr::Tuple(target) = &generator.target else {
                return;
            };
            let [target_key, target_value] = target.elts.as_slice() else {
                return;
            };
            if generator.ifs.is_empty()
                && !generator.is_async
                && same_name(key, target_key)
                && same_name(comp.value.as_ref(), target_value)
            {
                issues.push(issue_at(
                    "python:S7500",
                    "Copy the iterable directly instead of using a comprehension that only renames.",
                    comp.range(),
                    index,
                    source,
                ));
            }
        }
        _ => {}
    });
    issues
}

fn same_name(left: &Expr, right: &Expr) -> bool {
    matches!((left, right), (Expr::Name(left), Expr::Name(right)) if left.id == right.id)
}
