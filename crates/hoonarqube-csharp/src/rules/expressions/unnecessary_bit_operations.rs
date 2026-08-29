use super::support::binary_operands;
use super::support::first_named_child;
use super::support::integer_literal_value;
use super::support::is_zero_literal;
use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_from_byte_offsets};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2437 — bit operations fold away when an operand makes them
/// constants.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(expression) {
            continue;
        }
        let Some((left, right)) = binary_operands(expression) else {
            continue;
        };
        let operator = operator_of(expression);
        let operator_node = expression
            .children(&mut expression.walk())
            .find(|child| !child.is_named() && Some(child.kind()) == operator)
            .unwrap_or(left);
        if let Some((start, end)) = redundant_part(left, right, operator_node, operator, source) {
            issues.push(issue(
                language,
                "S2437",
                "Remove this unnecessary bit operation.",
                range_from_byte_offsets(start, end, source),
            ));
        }
    }
    issues
}

fn redundant_part(
    left: Node<'_>,
    right: Node<'_>,
    operator_node: Node<'_>,
    operator: Option<&str>,
    source: &str,
) -> Option<(usize, usize)> {
    let redundant = |operand| match operator {
        Some("&") => is_negative_one(operand, source),
        Some("|" | "^") => is_zero_literal(operand, source),
        _ => false,
    };
    if redundant(right) {
        Some((operator_node.start_byte(), right.end_byte()))
    } else if redundant(left) {
        Some((left.start_byte(), operator_node.end_byte()))
    } else {
        None
    }
}

/// `-1`: a negated unit literal.
fn is_negative_one(operand: Node<'_>, source: &str) -> bool {
    operand.kind() == "prefix_unary_expression"
        && operator_of(operand) == Some("-")
        && first_named_child(operand).is_some_and(|literal| {
            literal.kind() == "integer_literal"
                && integer_literal_value(node_text(literal, source)) == Some(1)
        })
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2437_flags_constant_and_identity_bit_operations() {
        let bad = analyze_default(
            "class C { int M(int value) => (value & -1) + (value | 0) + (value ^ 0); }",
        );
        assert_eq!(with_key(&bad, "csharpsquid:S2437").len(), 3);

        let good = analyze_default("class C { int M(int value) => value | 1; }");
        assert!(with_key(&good, "csharpsquid:S2437").is_empty());
    }

    #[test]
    fn s2437_flags_identity_operands_on_either_side() {
        let report = analyze_default(
            "class C { int M(int value) => (-1 & value) + (0x0 | value) + (0U ^ value); }",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2437").len(), 3);
    }
}
