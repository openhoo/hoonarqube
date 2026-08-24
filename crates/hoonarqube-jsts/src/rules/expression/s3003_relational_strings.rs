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

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s3003_flags_relational_comparison_of_two_string_literals() {
        let findings = js_keys("if (\"a\" < \"b\") {}\nif (\"abc\" >= \"abd\") {}\n");
        assert_eq!(count_key(&findings, "javascript:S3003"), 2);
    }

    #[test]
    fn s3003_allows_variable_operands_and_equality() {
        let findings = js_keys("if (\"a\" < b) {}\nif (\"a\" === \"b\") {}\n");
        assert_eq!(count_key(&findings, "javascript:S3003"), 0);
    }

    #[test]
    fn s3003_empty_string_literals_still_compare_relationally() {
        let findings = js_keys("if (\"\" <= \"\") {}\n");
        assert_eq!(count_key(&findings, "javascript:S3003"), 1);
    }
}
