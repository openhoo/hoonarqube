// Rule module s3981_length_comparison (generated).
use super::walker::numeric_literal_value;
use crate::support::{IssueSink, RuleScope, static_property_name};
use oxc_ast::ast::{BinaryExpression, BinaryOperator};
use oxc_span::GetSpan;

/// `S3981`: `.length` comparisons that are always true or false.
pub(crate) fn check_length_comparison(sink: &mut IssueSink, it: &BinaryExpression<'_>) {
    let length_side = [&it.left, &it.right].iter().any(|operand| {
        let Some(member) = operand.as_member_expression() else {
            return false;
        };
        static_property_name(member) == Some("length")
    });
    let other = if it.left.as_member_expression().is_some() {
        &it.right
    } else {
        &it.left
    };
    let suspicious = length_side
        && (matches!(
            it.operator,
            BinaryOperator::LessThan
                | BinaryOperator::GreaterEqualThan
                | BinaryOperator::Equality
                | BinaryOperator::StrictEquality
        ) && numeric_literal_value(other).is_some_and(|value| value.eq(&-1.0) || value == 0.0));
    if suspicious {
        sink.emit_span(
            RuleScope::Both,
            "S3981",
            "Fix this always-true/false length comparison.",
            it.span(),
        );
    }
}
