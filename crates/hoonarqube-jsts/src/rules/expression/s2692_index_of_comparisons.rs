// Rule module s2692_index_of_comparisons (generated).
use hoonarqube_ir::{Issue};
use oxc_ast::ast::{BinaryExpression, BinaryOperator, CallExpression, Expression};
use oxc_span::{GetSpan};
use crate::context::{AnalysisContext};
use crate::support::{IssueSink, RuleScope};
use super::walker::{call_property, numeric_literal_value};


/// `S2692` (`indexOf(...) > 0`) and `S6557`
/// (`indexOf(...)[=|==|===] 0` / `lastIndexOf` equality shapes).
pub(crate) fn check_index_of_comparisons(sink: &mut IssueSink, it: &BinaryExpression<'_>) {
    let Expression::CallExpression(call) = &it.left else {
        return;
    };
    let Some((property, _)) = call_property(call) else {
        return;
    };
    if !matches!(property, "indexOf" | "lastIndexOf") {
        return;
    }
    let zero = numeric_literal_value(&it.right).is_some_and(|value| value == 0.0);
    if property == "indexOf" && it.operator == BinaryOperator::GreaterThan && zero {
        sink.emit_span(
            RuleScope::Both,
            "S2692",
            "Replace this comparison with \">= 0\" or \"!== -1\".",
            it.span(),
        );
    }
    if zero
        && matches!(
            it.operator,
            BinaryOperator::Equality | BinaryOperator::StrictEquality
        )
    {
        sink.emit_span(
            RuleScope::Both,
            "S6557",
            "Prefer \"startsWith()\"/\"includes()\" over this comparison.",
            it.span(),
        );
    }
}

pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    const KEYS: &[&str] = &["S2692"];
    let mut issues = super::walker::run(ctx);
    issues.retain(|i| {
        i.rule_key.rsplit(':').next().is_some_and(|k| KEYS.contains(&k))
    });
    issues
}
