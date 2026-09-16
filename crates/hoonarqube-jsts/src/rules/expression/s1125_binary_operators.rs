// Rule module s1125_binary_operators (generated).
use crate::rules::shared::is_equality_operator;
use crate::support::{IssueSink, RuleScope, identifier_name, unparenthesized};
use oxc_ast::ast::{
    BinaryExpression, BinaryOperator, Expression, LogicalExpression, LogicalOperator,
    UnaryExpression, UnaryOperator,
};
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
    ) && !eqeqeq_smart_exempt(it)
    {
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
        if matches!(operand, Expression::BooleanLiteral(_))
            && matches!(
                it.operator,
                BinaryOperator::Equality | BinaryOperator::Inequality
            )
        {
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

/// Whether `SonarJS` `eqeqeq` (default `smart`) exempts this loose
/// comparison: `== null`/`!= null` checks both `null` and `undefined`,
/// `typeof x == "…"` is a deliberate type probe, and comparing two
/// literals of the same type is already precise.
fn eqeqeq_smart_exempt(it: &BinaryExpression<'_>) -> bool {
    let left = unparenthesized(&it.left);
    let right = unparenthesized(&it.right);
    is_null_literal(left)
        || is_null_literal(right)
        || is_typeof_expression(left)
        || is_typeof_expression(right)
        || literal_type(left).is_some_and(|kind| Some(kind) == literal_type(right))
}

fn is_null_literal(expression: &Expression<'_>) -> bool {
    matches!(expression, Expression::NullLiteral(_))
}

fn is_typeof_expression(expression: &Expression<'_>) -> bool {
    matches!(
        expression,
        Expression::UnaryExpression(unary) if unary.operator == UnaryOperator::Typeof
    )
}

/// The `typeof` category of a literal operand, mirroring `ESLint`'s
/// `getLiteralType`: template literals without substitutions count as
/// strings.
fn literal_type(expression: &Expression<'_>) -> Option<&'static str> {
    match expression {
        Expression::NullLiteral(_) | Expression::RegExpLiteral(_) => Some("object"),
        Expression::BooleanLiteral(_) => Some("boolean"),
        Expression::NumericLiteral(_) => Some("number"),
        Expression::BigIntLiteral(_) => Some("bigint"),
        Expression::StringLiteral(_) => Some("string"),
        Expression::TemplateLiteral(template) => {
            template.expressions.is_empty().then_some("string")
        }
        _ => None,
    }
}
/// Reports the logical-expression cases covered by pinned S1125.
///
/// `allow_right_or` is true only when the caller is visiting a logical
/// expression that is the direct test of an `if` or conditional expression.
pub(crate) fn check_logical_operators(
    sink: &mut IssueSink,
    it: &LogicalExpression<'_>,
    allow_right_or: bool,
) {
    if let Expression::BooleanLiteral(literal) = unparenthesized(&it.left) {
        sink.emit_span(
            RuleScope::Both,
            "S1125",
            "Refactor the code to avoid using this boolean literal.",
            literal.span(),
        );
    }
    let report_right = it.operator == LogicalOperator::And
        || (it.operator == LogicalOperator::Or && allow_right_or);
    if report_right && let Expression::BooleanLiteral(literal) = unparenthesized(&it.right) {
        sink.emit_span(
            RuleScope::Both,
            "S1125",
            "Refactor the code to avoid using this boolean literal.",
            literal.span(),
        );
    }
}

/// Reports the unary `!true` / `!false` S1125 cases.
pub(crate) fn check_unary_boolean(sink: &mut IssueSink, it: &UnaryExpression<'_>) {
    if it.operator == UnaryOperator::LogicalNot
        && let Expression::BooleanLiteral(literal) = unparenthesized(&it.argument)
    {
        sink.emit_span(
            RuleScope::Both,
            "S1125",
            "Refactor the code to avoid using this boolean literal.",
            literal.span(),
        );
    }
}
#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s1125_flags_negated_boolean_literals() {
        let findings = js_keys("const a = !true;\nconst b = !false;\n");
        assert_eq!(count_key(&findings, "javascript:S1125"), 2);
    }

    #[test]
    fn s1125_ignores_nonliteral_negation() {
        let findings = js_keys("const a = !flag;\n");
        assert_eq!(count_key(&findings, "javascript:S1125"), 0);
    }

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

    #[test]
    fn s1440_exempts_null_comparisons() {
        // SonarJS eqeqeq defaults to "smart": `== null`/`!= null` check
        // both null and undefined and stay silent.
        let findings = js_keys(
            "function f(a, b) {\n  if (a == null) return 1;\n  if (b != null) return 2;\n  return 0;\n}\n",
        );
        assert_eq!(count_key(&findings, "javascript:S1440"), 0);

        let ts =
            ts_keys("declare const data: number[] | null | undefined;\nif (data == null) {}\n");
        assert_eq!(count_key(&ts, "typescript:S1440"), 0);
    }

    #[test]
    fn s1440_exempts_typeof_and_same_type_literal_comparisons() {
        let findings =
            js_keys("if (typeof x == \"object\") {}\nif (\"a\" == \"b\") {}\nif (1 == 2) {}\n");
        assert_eq!(count_key(&findings, "javascript:S1440"), 0);
    }

    #[test]
    fn s1440_still_flags_non_null_loose_equality() {
        let findings = js_keys(
            "function f(a, b) {\n  if (a == b) return 1;\n  if (a == 3) return 2;\n  if (a == undefined) return 3;\n  return 0;\n}\n",
        );
        assert_eq!(count_key(&findings, "javascript:S1440"), 3);
    }
}
