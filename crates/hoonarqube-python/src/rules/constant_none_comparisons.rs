use crate::support::constant_literal_text;
use crate::support::for_each_stmt_expr;
use crate::support::is_none_literal;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5727 — constant comparison to None -------------------------------

pub(crate) fn check_constant_none_comparisons(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Expr::Compare(compare) = expr else { return };
        let mut sides: Vec<&Expr> = vec![&compare.left];
        sides.extend(&compare.comparators);
        let constant_involved = sides.iter().any(|side| {
            is_none_literal(side)
                && sides.iter().any(|other| {
                    !std::ptr::eq(*side, *other) && constant_literal_text(other).is_some()
                })
        });
        if constant_involved {
            issues.push(issue_at(
                "python:S5727",
                "Review this comparison; it involves only constants and 'None'.",
                compare.range(),
                index,
                source,
            ));
        }
    });
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s5727_flags_constant_none_comparisons() {
        assert_eq!(
            findings(&scan("same = None == None\n"), "python:S5727").len(),
            1
        );
        assert_eq!(
            findings(&scan("odd = \"x\" == None\n"), "python:S5727").len(),
            1
        );
        assert!(findings(&scan("maybe = x == None\n"), "python:S5727").is_empty());
    }
}
