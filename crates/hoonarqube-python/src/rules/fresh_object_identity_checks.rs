use crate::support::for_each_stmt_expr;
use crate::support::is_freshly_created;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5796 — identity check on freshly created objects ----------------

pub(crate) fn check_fresh_object_identity_checks(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Expr::Compare(compare) = expr else { return };
        let identity = compare.ops.iter().any(|op| {
            matches!(
                op,
                ruff_python_ast::CmpOp::Is | ruff_python_ast::CmpOp::IsNot
            )
        });
        if !identity {
            return;
        }
        let mut sides: Vec<&Expr> = vec![&compare.left];
        sides.extend(&compare.comparators);
        if sides.iter().any(|side| is_freshly_created(side)) {
            issues.push(issue_at(
                "python:S5796",
                "Do not test freshly created objects for identity; compare values with '=='.",
                compare.range(),
                index,
                source,
            ));
        }
    });
    issues
}
