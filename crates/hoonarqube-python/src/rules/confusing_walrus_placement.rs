use crate::support::flag_comprehension_walrus;
use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5685 — confusing walrus operator placement ----------------------

pub(crate) fn check_confusing_walrus_placement(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| match expr {
        Expr::ListComp(comp) => flag_comprehension_walrus(&comp.elt, &mut issues, index, source),
        Expr::SetComp(comp) => flag_comprehension_walrus(&comp.elt, &mut issues, index, source),
        Expr::Generator(comp) => flag_comprehension_walrus(&comp.elt, &mut issues, index, source),
        Expr::DictComp(comp) => {
            if let Some(key) = &comp.key {
                flag_comprehension_walrus(key, &mut issues, index, source);
            }
            flag_comprehension_walrus(&comp.value, &mut issues, index, source);
        }
        Expr::Compare(compare) => {
            let chained = compare.ops.len() > 1;
            if chained {
                if matches!(compare.left.as_ref(), Expr::Named(_)) {
                    issues.push(issue_at(
                        "python:S5685",
                        "Move this walrus operator to a clearer location.",
                        compare.left.range(),
                        index,
                        source,
                    ));
                }
                for comparator in &compare.comparators {
                    if matches!(comparator, Expr::Named(_)) {
                        issues.push(issue_at(
                            "python:S5685",
                            "Move this walrus operator to a clearer location.",
                            comparator.range(),
                            index,
                            source,
                        ));
                    }
                }
            }
        }
        _ => {}
    });
    issues
}
