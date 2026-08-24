use super::support::comparisons;
use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1244 — floating-point equality needs a tolerance.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (expression, left, right) in comparisons(root) {
        let float_side = left.kind() == "real_literal" || right.kind() == "real_literal";
        if matches!(operator_of(expression), Some("==" | "!=")) && float_side {
            issues.push(issue(
                language,
                "S1244",
                "Compare floating-point values with a tolerance instead of equality.",
                range_of(expression),
            ));
        }
    }
    issues
}
