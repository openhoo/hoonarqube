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
