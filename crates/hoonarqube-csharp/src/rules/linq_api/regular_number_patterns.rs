use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{binary_operands, integer_literal_value, operator_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3937 — three-or-more equality literals over one identifier
/// should step regularly.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(expression) || operator_of(expression) != Some("||") {
            continue;
        }
        if expression.parent().is_some_and(|parent| {
            parent.kind() == "binary_expression" && operator_of(parent) == Some("||")
        }) {
            continue;
        }
        let operands = or_chain_operands(expression);
        let mut subject: Option<&str> = None;
        let mut values: Vec<i128> = Vec::new();
        let mut leaves: Vec<Node<'_>> = Vec::new();
        let mut regular_shape = true;
        for operand in &operands {
            let equality = operator_of(*operand) == Some("==")
                && binary_operands(*operand).is_some_and(|(left, right)| {
                    left.kind() == "identifier"
                        && right.kind() == "integer_literal"
                        && integer_literal_value(node_text(right, source)).is_some()
                        && {
                            let name = node_text(left, source);
                            match subject {
                                None => {
                                    subject = Some(name);
                                    true
                                }
                                Some(seen) => seen == name,
                            }
                        }
                });
            if !equality {
                regular_shape = false;
                break;
            }
            let (_, right) = binary_operands(*operand).unwrap_or((*operand, *operand));
            values.push(i128::from(
                integer_literal_value(node_text(right, source)).unwrap_or(0),
            ));
            leaves.push(*operand);
        }
        if !regular_shape || leaves.len() < 3 {
            continue;
        }
        let uniform = values
            .windows(2)
            .all(|pair| pair[1] - pair[0] == values[1] - values[0]);
        if !uniform {
            issues.push(issue(
                language,
                "S3937",
                "Make this sequence of compared numbers regular.",
                range_of(leaves[0]),
            ));
        }
    }
    issues
}

/// Flattens an `||` chain into its operands.
fn or_chain_operands(expression: Node<'_>) -> Vec<Node<'_>> {
    if operator_of(expression) == Some("||")
        && let Some((left, right)) = binary_operands(expression)
    {
        let mut operands = or_chain_operands(left);
        operands.extend(or_chain_operands(right));
        return operands;
    }
    vec![expression]
}
