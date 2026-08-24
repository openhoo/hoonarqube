use super::support::catch_type_tail;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::block_statements;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2486 — swallowing bare `Exception` hides unrelated bugs.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["catch_clause"])
        .into_iter()
        .filter(|clause| !is_error_tainted(*clause))
        .filter(|clause| catch_type_tail(*clause, source) == Some("Exception"))
        .filter(|clause| {
            clause
                .child_by_field_name("body")
                .is_some_and(|body| block_statements(body).is_empty())
        })
        .map(|clause| {
            issue(
                language,
                "S2486",
                "Handle this exception or narrow the catch clause.",
                range_of(clause),
            )
        })
        .collect()
}
