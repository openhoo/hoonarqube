use crate::support::dotted_name_in;
use crate::support::for_each_annotation;
use crate::support::for_each_expr;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_typing_alias_hints(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    const TYPING_ALIASES: [&str; 12] = [
        "typing.List",
        "typing.Dict",
        "typing.Set",
        "typing.Tuple",
        "typing.FrozenSet",
        "typing.Type",
        "List",
        "Dict",
        "Set",
        "Tuple",
        "FrozenSet",
        "Type",
    ];
    let mut issues = Vec::new();
    for_each_annotation(parsed.syntax().body.as_slice(), &mut |annotation| {
        for_each_expr(annotation, &mut |expr| {
            if dotted_name_in(expr, &TYPING_ALIASES) {
                issues.push(issue_at(
                    "python:S6545",
                    "Use builtin generics instead of the typing alias.",
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
    fn s6545_prefers_builtin_generics_over_typing_aliases() {
        let flagged =
            scan("def f() -> List[int]:\n    return []\ndef g() -> list[int]:\n    return []\n");
        assert_eq!(findings(&flagged, "python:S6545").len(), 1);
    }
}
