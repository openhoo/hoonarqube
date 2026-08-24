use super::support::else_alternative;
use super::support::is_else_alternative;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S126 — `else if` chains end with a terminal `else`.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for head in collect_kinds(root, &["if_statement"]) {
        if is_error_tainted(head) || is_else_alternative(head) {
            continue;
        }
        let mut current = head;
        loop {
            match else_alternative(current) {
                None => {
                    if current != head {
                        issues.push(issue(
                            language,
                            "S126",
                            "Add an 'else' clause to close this 'else if' chain.",
                            range_of(current),
                        ));
                    }
                    break;
                }
                Some(alternative) if alternative.kind() == "if_statement" => {
                    current = alternative;
                }
                Some(_) => break,
            }
        }
    }
    issues
}
