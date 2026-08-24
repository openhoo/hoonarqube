use super::support::comparisons;
use super::support::expression_name;
use super::support::first_named_child;
use super::support::is_zero_literal;
use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2692 — '`IndexOf`' presence tests use '>=' not '>'.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    fn indexof_call(operand: Node<'_>, source: &str) -> bool {
        operand.kind() == "invocation_expression"
            && first_named_child(operand).is_some_and(|callee| {
                callee.kind() == "member_access_expression"
                    && matches!(
                        expression_name(callee, source),
                        Some("IndexOf" | "LastIndexOf")
                    )
            })
    }
    let mut issues = Vec::new();
    for (expression, left, right) in comparisons(root) {
        let pattern = operator_of(expression) == Some(">")
            && ((indexof_call(left, source) && is_zero_literal(right, source))
                || (indexof_call(right, source) && is_zero_literal(left, source)));
        if pattern {
            issues.push(issue(
                language,
                "S2692",
                "Test 'IndexOf' results with '>= 0'; '>' wrongly rejects index 0.",
                range_of(expression),
            ));
        }
    }
    issues
}
