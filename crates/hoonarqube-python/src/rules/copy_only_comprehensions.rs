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

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    #[test]
    fn s7500_exempts_async_copies_but_preserves_synchronous_findings() {
        let source = concat!(
            "async def copies(qs, items, pairs):\n",
            "    async_list = [obj async for obj in qs]\n",
            "    async_set = {obj async for obj in qs}\n",
            "    async_generator = (obj async for obj in qs)\n",
            "    async_dict = {key: value async for key, value in pairs}\n",
            "    sync_list = [obj for obj in items]\n",
            "    sync_set = {obj for obj in items}\n",
            "    sync_generator = (obj for obj in items)\n",
            "    sync_dict = {key: value for key, value in pairs}\n",
        );
        let report = scan(source);
        let ranges: Vec<_> = findings(&report, "python:S7500")
            .into_iter()
            .map(|issue| (issue.range.start, issue.range.end))
            .collect();
        assert_eq!(
            ranges,
            vec![
                (pos(6, 16), pos(6, 38)),
                (pos(7, 15), pos(7, 37)),
                (pos(8, 21), pos(8, 43)),
                (pos(9, 16), pos(9, 52)),
            ]
        );
    }
}
