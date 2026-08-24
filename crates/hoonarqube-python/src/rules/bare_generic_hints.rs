use crate::support::for_each_annotation;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_bare_generic_hints(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    const BARE_GENERICS: [&str; 6] = ["list", "dict", "set", "tuple", "type", "frozenset"];
    let mut issues = Vec::new();
    for_each_annotation(parsed.syntax().body.as_slice(), &mut |annotation| {
        if matches!(annotation, Expr::Name(name) if BARE_GENERICS.contains(&name.id.as_str())) {
            issues.push(issue_at(
                "python:S6543",
                "Parameterize this generic type hint.",
                annotation.range(),
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
    fn s6543_flags_bare_generic_hints() {
        let flagged = scan(
            "def first(xs: list) -> int:\n    return 1\ndef second(xs: list[int]) -> int:\n    return 1\n",
        );
        assert_eq!(findings(&flagged, "python:S6543").len(), 1);
    }
}
