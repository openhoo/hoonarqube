// Rule module s2692_index_of_comparisons (generated).
use super::walker::{call_property, numeric_literal_value};
use crate::support::{IssueSink, RuleScope};
use oxc_ast::ast::{BinaryExpression, BinaryOperator, Expression};
use oxc_span::GetSpan;

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

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s2692_flags_indexof_greater_than_zero() {
        let findings = js_keys("if (s.indexOf(x) > 0) {}\n");
        assert_eq!(count_key(&findings, "javascript:S2692"), 1);
    }

    #[test]
    fn s2692_allows_gte_zero_and_nonzero_bounds() {
        let findings = js_keys("if (s.indexOf(x) >= 0) {}\nif (s.indexOf(x) > 1) {}\n");
        assert_eq!(count_key(&findings, "javascript:S2692"), 0);
    }

    #[test]
    fn s6557_flags_equality_with_zero_for_index_and_lastindexof() {
        let findings = js_keys("if (s.indexOf(x) === 0) {}\nif (s.lastIndexOf(y) == 0) {}\n");
        assert_eq!(count_key(&findings, "javascript:S6557"), 2);
        assert_eq!(count_key(&findings, "javascript:S2692"), 0);
    }
}
