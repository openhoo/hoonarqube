// Rule module s3003_relational_strings (generated).
use crate::support::{IssueSink, RuleScope};
use oxc_ast::ast::{BinaryExpression, BinaryOperator, Expression};
use oxc_span::GetSpan;

/// `S3003`: relational operators on two string literals.
pub(crate) fn check_relational_strings(sink: &mut IssueSink, it: &BinaryExpression<'_>) {
    if matches!(
        it.operator,
        BinaryOperator::LessThan
            | BinaryOperator::LessEqualThan
            | BinaryOperator::GreaterThan
            | BinaryOperator::GreaterEqualThan
    ) && matches!(&it.left, Expression::StringLiteral(_))
        && matches!(&it.right, Expression::StringLiteral(_))
    {
        sink.emit_span(
            RuleScope::Both,
            "S3003",
            "Do not compare string literals relationally.",
            it.span(),
        );
    }
}
