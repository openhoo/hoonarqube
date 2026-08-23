// Rule module s6644_redundant_ternary (generated).
use crate::support::{IssueSink, RuleScope};
use oxc_ast::ast::{ConditionalExpression, Expression};
use oxc_span::GetSpan;

/// `S6644`: `x ? true : false` and `x ? y : y` redundant shapes.
pub(crate) fn check_redundant_ternary(sink: &mut IssueSink, it: &ConditionalExpression<'_>) {
    let redundant = match (&it.consequent, &it.alternate) {
        (Expression::BooleanLiteral(consequent), Expression::BooleanLiteral(alternate)) => {
            consequent.value && !alternate.value
        }
        (Expression::Identifier(consequent), Expression::Identifier(alternate)) => {
            consequent.name == alternate.name
        }
        _ => false,
    };
    if redundant {
        sink.emit_span(
            RuleScope::Both,
            "S6644",
            "Replace this redundant ternary with the condition itself.",
            it.span(),
        );
    }
}
