use super::support::first_named_child;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::structure::{else_alternative, is_else_alternative};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1862 — a condition repeats along its if/else-if chain. Each
/// chain reports from its own first `if`.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for header in collect_kinds(root, &["if_statement"]) {
        if is_error_tainted(header) || is_else_alternative(header) {
            continue;
        }
        let mut seen: Vec<&str> = Vec::new();
        let mut current = Some(header);
        while let Some(if_statement) = current {
            if let Some(condition) =
                first_named_child(if_statement).filter(|condition| !is_error_tainted(*condition))
            {
                let text = node_text(condition, source);
                if seen.contains(&text) {
                    issues.push(issue(
                        language,
                        "S1862",
                        "This condition repeats an earlier check in the same chain.",
                        range_of(condition),
                    ));
                } else {
                    seen.push(text);
                }
            }
            current = else_alternative(if_statement)
                .filter(|alternative| alternative.kind() == "if_statement");
        }
    }
    issues
}
