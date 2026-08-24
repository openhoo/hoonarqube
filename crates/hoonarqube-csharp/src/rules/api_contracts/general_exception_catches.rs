use super::support::catch_type_tail;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2221 — catching bare `Exception` also swallows unrelated
/// runtime failures.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["catch_clause"])
        .into_iter()
        .filter(|clause| !is_error_tainted(*clause))
        .filter(|clause| catch_type_tail(*clause, source) == Some("Exception"))
        .map(|clause| {
            issue(
                language,
                "S2221",
                "Catch a more specific exception than 'Exception'.",
                range_of(clause),
            )
        })
        .collect()
}
