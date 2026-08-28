use super::support::binary_operator;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of, to_u32};
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1067 — one expression chains at most the tolerated number
/// of logical operators.
pub(crate) fn check(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(expression)
            || !matches!(binary_operator(expression, source), "&&" | "||")
        {
            continue;
        }
        let parent_is_logical_chain = expression.parent().is_some_and(|parent| {
            parent.kind() == "binary_expression"
                && matches!(binary_operator(parent, source), "&&" | "||")
        });
        if parent_is_logical_chain {
            continue;
        }
        let count = logical_operator_count(expression, source);
        if count > options.maximum_logical_operators {
            issues.push(issue(
                language,
                "S1067",
                format!(
                    "Reduce the number of conditional operators ({count}) used in the expression (maximum allowed {}).",
                    options.maximum_logical_operators
                ),
                range_of(expression, source),
            ));
        }
    }
    issues
}

/// Logical-operator occurrences within an expression subtree.
fn logical_operator_count(expression: Node<'_>, source: &str) -> u32 {
    to_u32(
        collect_kinds(expression, &["binary_expression"])
            .iter()
            .filter(|operand| matches!(binary_operator(**operand, source), "&&" | "||"))
            .count(),
    )
}
