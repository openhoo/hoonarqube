use super::support::boolean_literal_side;
use super::support::comparisons;
use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1125 — identity comparisons against boolean literals drop
/// the literal.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (expression, left, right) in comparisons(root) {
        let literal = boolean_literal_side(left, right, source);
        let redundant = matches!(
            (operator_of(expression), literal),
            (Some("=="), Some(true)) | (Some("!="), Some(false))
        );
        if redundant {
            issues.push(issue(
                language,
                "S1125",
                "Remove the redundant boolean literal from this comparison.",
                range_of(expression),
            ));
        }
    }
    issues
}
