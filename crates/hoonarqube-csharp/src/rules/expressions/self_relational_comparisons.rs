use super::support::comparisons;
use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2198 — relational self-comparisons are always constant.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (expression, left, right) in comparisons(root) {
        if !matches!(operator_of(expression), Some("<" | ">" | "<=" | ">=")) {
            continue;
        }
        if node_text(left, source).trim() == node_text(right, source).trim() {
            issues.push(issue(
                language,
                "S2198",
                "Remove this contradictory comparison of an expression with itself.",
                range_of(expression, source),
            ));
        }
    }
    issues
}
