use crate::engine::file_context::FileContext;
use crate::support::flag_comprehension_walrus;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;

// --- python:S5685 — confusing walrus operator placement ----------------------

pub(crate) fn check_confusing_walrus_placement(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        match expr {
            Expr::ListComp(comp) => {
                flag_comprehension_walrus(&comp.elt, &mut issues, index, source);
            }
            Expr::SetComp(comp) => flag_comprehension_walrus(&comp.elt, &mut issues, index, source),
            Expr::Generator(comp) => {
                flag_comprehension_walrus(&comp.elt, &mut issues, index, source);
            }
            Expr::DictComp(comp) => {
                if let Some(key) = &comp.key {
                    flag_comprehension_walrus(key, &mut issues, index, source);
                }
                flag_comprehension_walrus(&comp.value, &mut issues, index, source);
            }
            Expr::Compare(compare) => {
                let chained = compare.ops.len() > 1;
                if chained {
                    flag_comprehension_walrus(&compare.left, &mut issues, index, source);
                    for comparator in &compare.comparators {
                        flag_comprehension_walrus(comparator, &mut issues, index, source);
                    }
                }
            }
            _ => {}
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s5685_flags_confusing_walrus_positions() {
        assert_eq!(
            findings(&scan("vals = [y := get(y) for y in ys]\n"), "python:S5685").len(),
            1
        );
        assert_eq!(
            findings(&scan("mid = a < (b := c) < d\n"), "python:S5685").len(),
            1
        );
        assert!(
            findings(
                &scan("kept = [y for y in ys if (mark := y)]\n"),
                "python:S5685"
            )
            .is_empty()
        );
    }
}
