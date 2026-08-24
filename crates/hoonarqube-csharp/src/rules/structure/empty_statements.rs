use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1116 — stray empty statements are removed.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["empty_statement"])
        .into_iter()
        .filter(|statement| !is_error_tainted(*statement))
        .map(|statement| {
            issue(
                language,
                "S1116",
                "Remove this empty statement.",
                range_of(statement),
            )
        })
        .collect()
}
