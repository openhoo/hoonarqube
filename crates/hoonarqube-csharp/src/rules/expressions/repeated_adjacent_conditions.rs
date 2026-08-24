use super::support::block_statements;
use super::support::first_named_child;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2760 — adjacent if statements rechecking the same condition.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for block in collect_kinds(root, &["block"]) {
        let statements = block_statements(block);
        for pair in statements.windows(2) {
            let (first, second) = (pair[0], pair[1]);
            if first.kind() != "if_statement" || second.kind() != "if_statement" {
                continue;
            }
            let (Some(first_condition), Some(second_condition)) =
                (first_named_child(first), first_named_child(second))
            else {
                continue;
            };
            if !is_error_tainted(second_condition)
                && node_text(first_condition, source) == node_text(second_condition, source)
            {
                issues.push(issue(
                    language,
                    "S2760",
                    "This condition repeats the immediately preceding check.",
                    range_of(second_condition),
                ));
            }
        }
    }
    issues
}
