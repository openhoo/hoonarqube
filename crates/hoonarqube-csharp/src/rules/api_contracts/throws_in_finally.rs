use crate::CsLanguage;
use crate::cst::{ancestors_of, collect_kinds, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1163 — throwing from `finally` swallows in-flight failures.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["throw_statement"])
        .into_iter()
        .filter(|throw| ancestors_of(*throw).any(|ancestor| ancestor.kind() == "finally_clause"))
        .map(|throw| {
            issue(
                language,
                "S1163",
                "Do not throw from a finally block.",
                range_of(throw),
            )
        })
        .collect()
}
