// Rule module s2692_index_of_comparisons (generated).
use super::walker::numeric_literal_value;
use crate::rules::shared::call_property;
use crate::support::{IssueSink, RuleScope, source_slice, unparenthesized};
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

/// `S6557` direct-index form: comparing a single indexed character with a
/// one-character string literal (`ext[0] !== '.'`) is semantically the
/// same `startsWith`/`endsWith` recommendation. Kept conservative: only
/// plain references indexed at the first character or their own
/// `length - 1`, and exact one-character string literals qualify.
pub(crate) fn check_direct_index_comparison(
    sink: &mut IssueSink,
    source: &str,
    it: &BinaryExpression<'_>,
) {
    if !matches!(
        it.operator,
        BinaryOperator::Equality
            | BinaryOperator::Inequality
            | BinaryOperator::StrictEquality
            | BinaryOperator::StrictInequality
    ) {
        return;
    }
    let boundary = is_boundary_comparison(&it.left, &it.right, source)
        || is_boundary_comparison(&it.right, &it.left, source);
    if boundary {
        sink.emit_span(
            RuleScope::Both,
            "S6557",
            "Use \"startsWith()\"/\"endsWith()\" instead of this comparison.",
            it.span(),
        );
    }
}

/// Whether `indexed[...] (op) literal` is a single-character boundary
/// check.
fn is_boundary_comparison(
    indexed: &Expression<'_>,
    literal: &Expression<'_>,
    source: &str,
) -> bool {
    if !single_character_literal(literal) {
        return false;
    }
    let Expression::ComputedMemberExpression(member) = unparenthesized(indexed) else {
        return false;
    };
    plain_reference(&member.object) && boundary_index(&member.expression, &member.object, source)
}

/// The qualifying indices: the first character, or the reference's own
/// `length - 1` (suffix). Other positions are not boundary checks.
fn boundary_index(index: &Expression<'_>, owner: &Expression<'_>, source: &str) -> bool {
    if let Expression::NumericLiteral(numeric) = unparenthesized(index) {
        return numeric.value == 0.0;
    }
    let Expression::BinaryExpression(binary) = unparenthesized(index) else {
        return false;
    };
    if binary.operator != BinaryOperator::Subtraction {
        return false;
    }
    let Expression::StaticMemberExpression(length) = unparenthesized(&binary.left) else {
        return false;
    };
    length.property.name == "length"
        && numeric_literal_value(&binary.right) == Some(1.0)
        && plain_reference(&length.object)
        && source_slice(source, length.object.span()) == source_slice(source, owner.span())
}

/// Whether the expression is a plain reference: an identifier, `this`, or
/// a static member chain over such a base.
fn plain_reference(expression: &Expression<'_>) -> bool {
    match unparenthesized(expression) {
        Expression::Identifier(_) | Expression::ThisExpression(_) => true,
        Expression::StaticMemberExpression(member) => plain_reference(&member.object),
        _ => false,
    }
}

/// Whether the expression is a string literal holding exactly one UTF-16
/// code unit (so indexing actually compares that character).
fn single_character_literal(expression: &Expression<'_>) -> bool {
    match unparenthesized(expression) {
        Expression::StringLiteral(literal) => literal.value.encode_utf16().count() == 1,
        _ => false,
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

    #[test]
    fn s6557_flags_direct_index_boundary_comparisons() {
        // #251: comparing a single indexed character with a one-character
        // string is the direct form of the startsWith/endsWith
        // recommendation, in both operand orders and equality flavors.
        let findings = js_keys(
            "if (ext[0] !== '.') {}\nif (s[0] === 'a') {}\nif ('a' == s[0]) {}\nif (s[s.length - 1] !== 'x') {}\n",
        );
        assert_eq!(count_key(&findings, "javascript:S6557"), 4);
    }

    #[test]
    fn s6557_direct_index_controls_stay_clean() {
        let findings = js_keys(
            "if (s[0] === 'ab') {}\nif (s[0] === '') {}\nif (s[1] === 'a') {}\nif (arr[0] === 5) {}\nif (s[0] < 'a') {}\nif (s[0]) {}\nif (s[n] === 'a') {}\n",
        );
        assert_eq!(count_key(&findings, "javascript:S6557"), 0);
        assert_eq!(count_key(&findings, "javascript:S2692"), 0);
    }

    #[test]
    fn s6557_reports_pinned_express_direct_index_prefix() {
        // #251: verbatim expressjs/express@53d4a0d606c0388f764f192b306ce0e90200e7e8
        // lib/application.js (MIT). SonarQube 26.8.0.126808 (Sonar way)
        // reports exactly one S6557 in this file, the direct first-character
        // prefix check at line 300.
        let report = js(include_str!(
            "../../../fixtures/shapes/express-application.js"
        ));
        let sites: Vec<(u32, u32)> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S6557")
            .map(|issue| (issue.range.start.line, issue.range.start.column))
            .collect();
        assert_eq!(sites, vec![(300, 18)]);
    }
}
