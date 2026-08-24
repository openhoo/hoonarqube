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

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6644_flags_boolean_and_identical_branch_ternaries() {
        let findings = js_keys("v = cond ? true : false;\nw = cond ? x : x;\n");
        assert_eq!(count_key(&findings, "javascript:S6644"), 2);
    }

    #[test]
    fn s6644_allows_distinct_branches() {
        let findings = js_keys("v = cond ? 1 : 2;\nw = cond ? x : y;\n");
        assert_eq!(count_key(&findings, "javascript:S6644"), 0);
    }

    #[test]
    fn s6644_inverted_boolean_ternary_is_meaningful() {
        let findings = js_keys("v = cond ? false : true;\n");
        assert_eq!(count_key(&findings, "javascript:S6644"), 0);
    }
}
