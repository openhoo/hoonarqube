// Rule module s1125_binary_operators (generated).
use crate::rules::shared::is_equality_operator;
use crate::support::{IssueSink, RuleScope, identifier_name};
use oxc_ast::ast::{BinaryExpression, BinaryOperator, Expression};
use oxc_span::{GetSpan, Span};

/// Shared checks over one binary expression.
pub(crate) fn check_binary_operators(
    sink: &mut IssueSink,
    source: &str,
    it: &BinaryExpression<'_>,
) {
    if matches!(
        it.operator,
        BinaryOperator::Equality | BinaryOperator::Inequality
    ) {
        let (loose, strict) = match it.operator {
            BinaryOperator::Equality => ("==", "==="),
            BinaryOperator::Inequality => ("!=", "!=="),
            _ => unreachable!(),
        };
        let between_start = it.left.span().end;
        let between_end = it.right.span().start;
        let span = source
            .get(between_start as usize..between_end as usize)
            .and_then(|text| text.find(loose))
            .map_or(it.span(), |offset| {
                let start = between_start + u32::try_from(offset).unwrap_or_default();
                Span::new(start, start + 2)
            });
        sink.emit_span(
            RuleScope::Both,
            "S1440",
            &format!("Expected '{strict}' and instead saw '{loose}'."),
            span,
        );
    }
    for operand in [&it.left, &it.right] {
        if matches!(operand, Expression::BooleanLiteral(_)) && is_equality_operator(it.operator) {
            sink.emit_span(
                RuleScope::Both,
                "S1125",
                "Refactor the code to avoid using this boolean literal.",
                operand.span(),
            );
        }
        if identifier_name(operand) == Some("NaN") {
            sink.emit_span(
                RuleScope::Both,
                "S2688",
                "Use the isNaN function to compare with NaN.",
                it.span(),
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
