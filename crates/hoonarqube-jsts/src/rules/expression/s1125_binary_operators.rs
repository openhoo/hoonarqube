// Rule module s1125_binary_operators (generated).
use crate::rules::shared::is_equality_operator;
use crate::support::{IssueSink, RuleScope, identifier_name};
use oxc_ast::ast::{BinaryExpression, BinaryOperator, Expression};
use oxc_span::GetSpan;

/// Shared checks over one binary expression.
pub(crate) fn check_binary_operators(sink: &mut IssueSink, it: &BinaryExpression<'_>) {
    if matches!(
        it.operator,
        BinaryOperator::Equality | BinaryOperator::Inequality
    ) {
        sink.emit_span(
            RuleScope::Both,
            "S1440",
            "Replace this loose equality comparison with strict equality.",
            it.span(),
        );
    }
    for operand in [&it.left, &it.right] {
        if matches!(operand, Expression::BooleanLiteral(_)) && is_equality_operator(it.operator) {
            sink.emit_span(
                RuleScope::Both,
                "S1125",
                "Remove this comparison against a boolean literal.",
                operand.span(),
            );
        }
        if identifier_name(operand) == Some("NaN") {
            sink.emit_span(
                RuleScope::Both,
                "S2688",
                "Use \"Number.isNaN()\" instead of comparing to \"NaN\" directly.",
                operand.span(),
            );
        }
    }
    // `x === NaN` family: same operands, but the equality shape suggests the
    // dedicated rule.
    if is_equality_operator(it.operator)
        && [identifier_name(&it.left), identifier_name(&it.right)]
            .into_iter()
            .any(|name| name == Some("NaN"))
    {
        sink.emit_span(
            RuleScope::Both,
            "S6679",
            "Use \"Number.isNaN()\" to test for NaN.",
            it.span(),
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s1125_flags_boolean_literal_equality_operands() {
        let findings = js_keys("let a = x == true;\nlet b = y != false;\n");
        assert_eq!(count_key(&findings, "javascript:S1125"), 2);
        assert_eq!(count_key(&findings, "javascript:S1440"), 2);
    }

    #[test]
    fn s1125_allows_comparisons_without_boolean_literals() {
        let findings = js_keys("let a = x === y;\nlet b = flag ? 1 : 2;\n");
        assert_eq!(count_key(&findings, "javascript:S1125"), 0);
    }

    #[test]
    fn s1125_nan_comparison_yields_dedicated_rules_not_s1125() {
        let findings = js_keys("if (x === NaN) {}\n");
        assert_eq!(count_key(&findings, "javascript:S1125"), 0);
        assert_eq!(count_key(&findings, "javascript:S2688"), 1);
        assert_eq!(count_key(&findings, "javascript:S6679"), 1);
    }
}
