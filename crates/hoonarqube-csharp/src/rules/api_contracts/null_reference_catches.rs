use super::support::catch_type_tail;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1696 — catching `NullReferenceException` hides dereference
/// bugs.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["catch_clause"])
        .into_iter()
        .filter(|clause| !is_error_tainted(*clause))
        .filter(|clause| catch_type_tail(*clause, source) == Some("NullReferenceException"))
        .map(|clause| {
            issue(
                language,
                "S1696",
                "Do not catch 'NullReferenceException'.",
                range_of(clause),
            )
        })
        .collect()
}
