use super::support::binary_operands;
use super::support::expression_name;
use super::support::first_named_child;
use super::support::null_check_name;
use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4201 — null checks merge into 'is' patterns.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    fn is_pattern_name<'a>(operand: Node<'_>, source: &'a str) -> Option<&'a str> {
        if operand.kind() != "is_expression" {
            return None;
        }
        first_named_child(operand)
            .filter(|target| target.kind() == "identifier")
            .and_then(|target| expression_name(target, source))
    }
    let mut issues = Vec::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(expression) || operator_of(expression) != Some("&&") {
            continue;
        }
        let Some((left, right)) = binary_operands(expression) else {
            continue;
        };
        let redundant = [
            (
                null_check_name(left, source),
                is_pattern_name(right, source),
            ),
            (
                null_check_name(right, source),
                is_pattern_name(left, source),
            ),
        ]
        .iter()
        .any(|(null_name, pattern)| null_name.is_some() && *null_name == *pattern);
        if redundant {
            issues.push(issue(
                language,
                "S4201",
                "Drop the null check; the 'is' type test already rejects null.",
                range_of(expression),
            ));
        }
    }
    issues
}
