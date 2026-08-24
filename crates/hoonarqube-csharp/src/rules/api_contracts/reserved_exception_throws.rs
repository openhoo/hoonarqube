use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of, simple_name};
use crate::rules::expressions::creation_type_text;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S112 — reserved exception types say nothing about the
/// failure and force callers to over-catch.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["object_creation_expression"])
        .into_iter()
        .filter(|creation| !is_error_tainted(*creation))
        .filter(|creation| {
            RESERVED_EXCEPTION_TYPES.contains(&simple_name(creation_type_text(*creation, source)))
        })
        .map(|creation| {
            issue(
                language,
                "S112",
                "Throw a more specific exception than this reserved type.",
                range_of(creation),
            )
        })
        .collect()
}

/// Reserved exception types that carry no domain meaning.
const RESERVED_EXCEPTION_TYPES: [&str; 3] =
    ["Exception", "ApplicationException", "SystemException"];
