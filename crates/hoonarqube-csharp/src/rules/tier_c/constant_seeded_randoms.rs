use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of, simple_name};
use crate::rules::expressions::{creation_type_text, invocation_arguments};
use crate::rules::literals::argument_expression;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4347 — secure generation made predictable through constant
/// seeding. Honest subset: `Random`-typed creations with exactly one integer
/// literal seed argument.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["object_creation_expression"])
        .into_iter()
        .filter(|creation| !is_error_tainted(*creation))
        .filter(|creation| simple_name(creation_type_text(*creation, source)).ends_with("Random"))
        .filter(|creation| {
            let arguments = invocation_arguments(*creation);
            arguments.len() == 1 && argument_expression(arguments[0]).kind() == "integer_literal"
        })
        .map(|creation| {
            issue(
                language,
                "S4347",
                "Seed this generator unpredictably; a constant seed produces predictable values.",
                range_of(creation),
            )
        })
        .collect()
}
