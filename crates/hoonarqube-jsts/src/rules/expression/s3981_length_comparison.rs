// Rule module s3981_length_comparison (generated).
use super::walker::numeric_literal_value;
use crate::support::{IssueSink, RuleScope, static_property_name, unparenthesized};
use oxc_ast::ast::{BinaryExpression, BinaryOperator};
use oxc_span::GetSpan;

/// `S3981`: collection `.length`/`.size` comparisons against zero.
pub(crate) fn check_length_comparison(sink: &mut IssueSink, it: &BinaryExpression<'_>) {
    if !matches!(
        it.operator,
        BinaryOperator::LessThan | BinaryOperator::GreaterEqualThan
    ) {
        return;
    }
    let Some(member) = unparenthesized(&it.left).as_member_expression() else {
        return;
    };
    if !matches!(static_property_name(member), Some("length" | "size")) {
        return;
    }
    if !matches!(
        numeric_literal_value(&it.right),
        Some(value) if value == 0.0
    ) {
        return;
    }
    sink.emit_span(
        RuleScope::Both,
        "S3981",
        "Fix this always-true/false length comparison.",
        it.span(),
    );
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s3981_flags_length_and_size_zero_comparisons() {
        let findings = js_keys("if (list.length < 0) {}\nif (list.size >= 0) {}\n");
        assert_eq!(count_key(&findings, "javascript:S3981"), 2);
    }

    #[test]
    fn s3981_allows_meaningful_bounds_wrong_operators_and_operand_order() {
        let findings = js_keys(
            "if (list.length > 0) {}\n\
             if (list.length === 0) {}\n\
             if (list.length < -1) {}\n\
             if (0 < list.length) {}\n\
             if (0 === list.length) {}\n",
        );
        assert_eq!(count_key(&findings, "javascript:S3981"), 0);
    }
}
