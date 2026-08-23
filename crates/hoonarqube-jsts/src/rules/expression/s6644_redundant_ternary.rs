// Rule module s6644_redundant_ternary (generated).
use hoonarqube_ir::{Issue};
use oxc_ast::ast::{ConditionalExpression, Expression};
use oxc_span::{GetSpan};
use crate::context::{AnalysisContext};
use crate::support::{IssueSink, RuleScope};


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

pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    const KEYS: &[&str] = &["S6644"];
    let mut issues = super::walker::run(ctx);
    issues.retain(|i| {
        i.rule_key.rsplit(':').next().is_some_and(|k| KEYS.contains(&k))
    });
    issues
}
