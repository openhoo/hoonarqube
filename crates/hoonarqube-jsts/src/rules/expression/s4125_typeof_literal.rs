// Rule module s4125_typeof_literal (generated).
use crate::support::{IssueSink, RuleScope};
use oxc_ast::ast::{BinaryExpression, BinaryOperator, Expression, UnaryOperator};
use oxc_span::GetSpan;

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

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s4125_flags_typeof_comparison_outside_typeof_set() {
        let findings = js_keys("typeof x === \"strng\";\n\"num\" === typeof y;\n");
        assert_eq!(count_key(&findings, "javascript:S4125"), 2);
    }

    #[test]
    fn s4125_allows_real_typeof_results() {
        let findings = js_keys("typeof x === \"string\";\ntypeof y === \"undefined\";\n");
        assert_eq!(count_key(&findings, "javascript:S4125"), 0);
    }

    #[test]
    fn s4125_js_only_scope_suppresses_typescript_and_is_case_sensitive() {
        let ts_findings = ts_keys("typeof x === \"strng\";\n");
        assert_eq!(count_key(&ts_findings, "typescript:S4125"), 0);

        let cased = js_keys("typeof x === \"Strng\";\n");
        assert_eq!(count_key(&cased, "javascript:S4125"), 1);
    }
}
