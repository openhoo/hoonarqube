use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2583 — a condition that is literally `false` guards code
/// that can never run.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for header in collect_kinds(
        root,
        &[
            "if_statement",
            "while_statement",
            "for_statement",
            "conditional_expression",
        ],
    ) {
        if is_error_tainted(header) {
            continue;
        }
        let Some(condition) = header.child_by_field_name("condition") else {
            continue;
        };
        if condition.kind() == "boolean_literal" && node_text(condition, source) == "false" {
            issues.push(issue(
                language,
                "S2583",
                "This condition is always false; the guarded code never runs.",
                range_of(condition),
            ));
        }
    }
    issues
}
