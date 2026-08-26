use super::support::block_statements;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::structure::embedded_bodies;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3626 — a jump ending a loop body can never be reached any
/// differently than falling through. Switch sections require their `break`
/// and stay clean.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for header in collect_kinds(root, &LOOP_KINDS) {
        if is_error_tainted(header) {
            continue;
        }
        for body in embedded_bodies(header) {
            let tail: Vec<Node> = if body.kind() == "block" {
                block_statements(body)
            } else {
                vec![body]
            };
            let Some(last) = tail.last() else {
                continue;
            };
            if matches!(last.kind(), "break_statement" | "continue_statement") {
                issues.push(issue(
                    language,
                    "S3626",
                    "Remove this redundant jump.",
                    range_of(*last, source),
                ));
            }
        }
    }
    issues
}

/// Loop headers wrapping a body statement.
pub(crate) const LOOP_KINDS: [&str; 4] = [
    "for_statement",
    "foreach_statement",
    "while_statement",
    "do_statement",
];
