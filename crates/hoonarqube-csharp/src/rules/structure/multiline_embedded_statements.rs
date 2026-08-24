use super::support::EMBEDDED_HEADER_KINDS;
use super::support::embedded_bodies;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2681 — multi-line embedded bodies wear braces so no later
/// line can masquerade as part of the body.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for header in collect_kinds(root, &EMBEDDED_HEADER_KINDS) {
        if is_error_tainted(header) {
            continue;
        }
        for body in embedded_bodies(header) {
            if body.kind() != "block" && body.start_position().row != body.end_position().row {
                issues.push(issue(
                    language,
                    "S2681",
                    "Enclose this multi-line body in curly braces.",
                    range_of(body),
                ));
            }
        }
    }
    issues
}
