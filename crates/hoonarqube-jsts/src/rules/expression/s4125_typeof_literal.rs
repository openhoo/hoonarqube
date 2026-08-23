// Rule module s4125_typeof_literal (generated).
use hoonarqube_ir::{Issue};
use oxc_ast::ast::{BinaryExpression, BinaryOperator, Expression, StringLiteral, UnaryExpression, UnaryOperator};
use oxc_span::{GetSpan};
use crate::context::{AnalysisContext};
use crate::support::{IssueSink, RuleScope};


/// `S4125`: `typeof x === 'literal'` with a value outside the typeof set.
pub(crate) fn check_typeof_literal(sink: &mut IssueSink, it: &BinaryExpression<'_>) {
    if !matches!(
        it.operator,
        BinaryOperator::Equality | BinaryOperator::StrictEquality
    ) {
        return;
    }
    let typeof_operand = [&it.left, &it.right].into_iter().find(|operand| {
        matches!(
            operand,
            Expression::UnaryExpression(unary) if unary.operator == UnaryOperator::Typeof
        )
    });
    let literal_operand = [&it.left, &it.right]
        .into_iter()
        .find_map(|operand| match operand {
            Expression::StringLiteral(literal) => Some(literal.value.to_string()),
            _ => None,
        });
    if let (Some(_), Some(literal)) = (typeof_operand, literal_operand)
        && !TYPEOF_VALUES.contains(&literal.as_str())
    {
        sink.emit_span(
            RuleScope::JsOnly,
            "S4125",
            "This string is not a valid typeof result; fix the comparison.",
            it.span(),
        );
    }
}


/// The only values `typeof` may yield; `S4125` flags comparisons outside it.
pub(crate) const TYPEOF_VALUES: [&str; 8] = [
    "undefined",
    "object",
    "boolean",
    "number",
    "string",
    "symbol",
    "bigint",
    "function",
];

pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    const KEYS: &[&str] = &["S4125"];
    let mut issues = super::walker::run(ctx);
    issues.retain(|i| {
        i.rule_key.rsplit(':').next().is_some_and(|k| KEYS.contains(&k))
    });
    issues
}
