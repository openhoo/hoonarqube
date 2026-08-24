use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, invocation_receiver};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1858 — `.ToString()` on a receiver that already yields a
/// string. Subset: string/char/interpolated-string receivers only; calls on
/// typed variables need semantic typing and stay uncovered.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| callee_name(*call, source) == Some("ToString"))
        .filter(|call| {
            invocation_receiver(*call).is_some_and(|receiver| {
                matches!(
                    receiver.kind(),
                    "string_literal" | "character_literal" | "interpolated_string_expression"
                )
            })
        })
        .map(|call| {
            issue(
                language,
                "S1858",
                "Remove this redundant 'ToString' call.",
                range_of(call),
            )
        })
        .collect()
}
