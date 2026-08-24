use crate::support::for_each_annotation;
use crate::support::for_each_expr;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6542 / S6543 / S6545 / S6546 — hint shapes -------------------------

pub(crate) fn check_any_type_hints(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_annotation(parsed.syntax().body.as_slice(), &mut |annotation| {
        for_each_expr(annotation, &mut |expr| {
            if matches!(expr, Expr::Name(name) if name.id.as_str() == "Any") {
                issues.push(issue_at(
                    "python:S6542",
                    "Do not use Any as a type hint.",
                    expr.range(),
                    index,
                    source,
                ));
            }
        });
    });
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s6542_flags_any_type_hints() {
        let flagged = scan("def f(x: Any) -> int:\n    return 1\n");
        assert_eq!(findings(&flagged, "python:S6542").len(), 1);
    }
}
