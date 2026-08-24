use super::support::comparisons;
use super::support::expression_name;
use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2688 — NaN compares unequal to everything, itself included.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (expression, left, right) in comparisons(root) {
        if !matches!(operator_of(expression), Some("==" | "!=")) {
            continue;
        }
        let names_nan = [left, right]
            .iter()
            .any(|operand| expression_name(*operand, source) == Some("NaN"));
        if names_nan {
            issues.push(issue(
                language,
                "S2688",
                "Use 'IsNaN' to test for NaN; equality comparisons never hold.",
                range_of(expression),
            ));
        }
    }
    issues
}
