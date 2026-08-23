// Rule module s1125_binary_operators (generated).
use hoonarqube_ir::{Issue};
use oxc_ast::ast::{BinaryExpression, BinaryOperator, Expression};
use oxc_span::{GetSpan};
use crate::context::{AnalysisContext};
use crate::support::{IssueSink, RuleScope, identifier_name};
use super::walker::{is_equality_operator};


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

pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    const KEYS: &[&str] = &["S1125", "S1440"];
    let mut issues = super::walker::run(ctx);
    issues.retain(|i| {
        i.rule_key.rsplit(':').next().is_some_and(|k| KEYS.contains(&k))
    });
    issues
}
