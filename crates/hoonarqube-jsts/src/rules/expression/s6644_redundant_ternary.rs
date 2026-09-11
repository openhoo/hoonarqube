// Rule module s6644_redundant_ternary (generated).
use crate::support::{IssueSink, RuleScope};
use oxc_ast::ast::{ConditionalExpression, Expression};
use oxc_span::GetSpan;

/// `S6644`: conditional expressions with a simpler boolean/default form.
pub(crate) fn check_redundant_ternary(sink: &mut IssueSink, it: &ConditionalExpression<'_>) {
    let boolean_literals = matches!(
        (&it.consequent, &it.alternate),
        (Expression::BooleanLiteral(_), Expression::BooleanLiteral(_))
    );
    let default_assignment = matches!(
        (&it.test, &it.consequent),
        (Expression::Identifier(test), Expression::Identifier(consequent))
            if test.name == consequent.name
    );
    if boolean_literals || default_assignment {
        let message = if boolean_literals {
            "Unnecessary use of boolean literals in conditional expression."
        } else {
            "Unnecessary use of conditional expression for default assignment."
        };
        sink.emit_span(RuleScope::Both, "S6644", message, it.span());
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6644_flags_both_boolean_literal_orientations() {
        let findings = js_keys("v = cond ? true : false;\nw = cond ? false : true;\n");
        assert_eq!(count_key(&findings, "javascript:S6644"), 2);
    }

    #[test]
    fn s6644_keeps_dynamic_and_non_boolean_alternatives_clean() {
        let findings = js_keys(
            "v = cond ? maybe : false;\n\
             w = cond ? false : maybe;\n\
             x = cond ? 1 : 2;\n\
             y = cond ? left : right;\n",
        );
        assert_eq!(count_key(&findings, "javascript:S6644"), 0);
    }

    #[test]
    fn s6644_retains_the_legacy_inverted_fixture_as_a_positive_regression() {
        let findings = js_keys("const r = flag ? false : true;\n");
        assert_eq!(count_key(&findings, "javascript:S6644"), 1);
    }

    #[test]
    fn s6644_only_uses_identifier_default_assignment_shape() {
        let findings = js_keys(
            "const first = flag ? flag : fallback;\n\
             const side_effect = read() ? read() : fallback;\n\
             const member = object.flag ? object.flag : fallback;\n",
        );
        assert_eq!(count_key(&findings, "javascript:S6644"), 1);
        assert_eq!(
            findings
                .iter()
                .filter(|(key, _)| key == "javascript:S6644")
                .count(),
            1
        );
    }
}
