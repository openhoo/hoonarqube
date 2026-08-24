use super::support::EMBEDDED_HEADER_KINDS;
use super::support::embedded_bodies;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S121 — control structures wrap their bodies in curly braces.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for header in collect_kinds(root, &EMBEDDED_HEADER_KINDS) {
        if is_error_tainted(header) {
            continue;
        }
        for body in embedded_bodies(header) {
            if body.kind() != "block" {
                issues.push(issue(
                    language,
                    "S121",
                    "Add curly braces around this embedded statement.",
                    range_of(body),
                ));
            }
        }
    }
    issues
}
