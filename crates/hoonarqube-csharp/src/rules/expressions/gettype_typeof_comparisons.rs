use super::support::comparisons;
use super::support::expression_name;
use super::support::first_named_child;
use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2219 — GetType()/typeof(X) pairs become 'is' patterns.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (expression, left, right) in comparisons(root) {
        if !matches!(operator_of(expression), Some("==" | "!=")) {
            continue;
        }
        let pattern = (gettype_invocation(left, source) && right.kind() == "typeof_expression")
            || (gettype_invocation(right, source) && left.kind() == "typeof_expression");
        if pattern {
            issues.push(issue(
                language,
                "S2219",
                "Use the 'is' type pattern instead of comparing GetType() with typeof().",
                range_of(expression, source),
            ));
        }
    }
    issues
}

/// Zero-argument `GetType()` invocation.
fn gettype_invocation(operand: Node<'_>, source: &str) -> bool {
    if operand.kind() != "invocation_expression" {
        return false;
    }
    let Some(callee) = first_named_child(operand) else {
        return false;
    };
    callee.kind() == "member_access_expression"
        && expression_name(callee, source) == Some("GetType")
        && collect_kinds(operand, &["argument_list"])
            .iter()
            .all(|list| list.named_child_count() == 0)
}
