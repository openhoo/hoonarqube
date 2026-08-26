use crate::support::dotted_name_in;
use crate::support::for_each_annotation;
use crate::support::for_each_expr;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_typing_union_hints(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_annotation(parsed.syntax().body.as_slice(), &mut |annotation| {
        for_each_expr(annotation, &mut |expr| {
            if let Expr::Subscript(subscript) = expr
                && dotted_name_in(&subscript.value, &["typing.Union", "Union"])
            {
                issues.push(issue_at(
                    "python:S6546",
                    "Use PEP 604 unions (X | Y) instead of typing.Union.",
                    subscript.range(),
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
    fn s6546_prefers_pep604_unions() {
        let flagged = scan(
            "def f(x: Union[int, str]) -> int:\n    return 1\ndef g(x: int | str) -> int:\n    return 1\n",
        );
        assert_eq!(findings(&flagged, "python:S6546").len(), 1);
    }
}
