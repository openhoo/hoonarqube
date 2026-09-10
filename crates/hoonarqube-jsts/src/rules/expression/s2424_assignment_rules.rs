// Rule module s2424_assignment_rules (generated).
use super::s1442_plain_calls::BUILTIN_GLOBALS;
use crate::support::{IssueSink, RuleScope};
use oxc_ast::ast::{AssignmentExpression, AssignmentOperator, Expression, UnaryOperator};
use oxc_span::{GetSpan, Span};

/// `S2757` (the `x =+ 1` typo), `S6643`/`S2424` (writes into built-ins).
/// Emits the S2757 sign-swap finding for an assignment or variable
/// initializer. The assignment token must touch the unary operator, while
/// the unary operator must be separated from its operand; otherwise `=+1`
/// is a legitimate assignment of a positive value rather than a typo.
pub(crate) fn check_sign_swap(
    sink: &mut IssueSink,
    source: &str,
    unary: &oxc_ast::ast::UnaryExpression<'_>,
) {
    if !matches!(
        unary.operator,
        UnaryOperator::UnaryPlus | UnaryOperator::UnaryNegation | UnaryOperator::LogicalNot
    ) {
        return;
    }
    let unary_start = unary.span.start as usize;
    let Some(equal_before) = unary_start.checked_sub(1) else {
        return;
    };
    if source.as_bytes().get(equal_before) != Some(&b'=') {
        return;
    }
    if equal_before > 0
        && matches!(
            source.as_bytes()[equal_before - 1],
            b'=' | b'!'
                | b'<'
                | b'>'
                | b'+'
                | b'-'
                | b'*'
                | b'/'
                | b'%'
                | b'&'
                | b'|'
                | b'^'
                | b'?'
        )
    {
        return;
    }
    let argument_start = unary.argument.span().start as usize;
    if argument_start <= unary_start.saturating_add(1) {
        return;
    }
    sink.emit_span(
        RuleScope::Both,
        "S2757",
        &format!(
            "Was \"{}=\" meant instead?",
            match unary.operator {
                UnaryOperator::UnaryPlus => "+",
                UnaryOperator::UnaryNegation => "-",
                UnaryOperator::LogicalNot => "!",
                _ => unreachable!(),
            }
        ),
        Span::new(unary.span.start.saturating_sub(1), unary.span.start + 1),
    );
}

pub(crate) fn check_assignment_rules(
    sink: &mut IssueSink,
    source: &str,
    it: &AssignmentExpression<'_>,
) {
    if it.operator == AssignmentOperator::Assign
        && let Expression::UnaryExpression(unary) = &it.right
    {
        check_sign_swap(sink, source, unary);
    }
    // Member assignment targets only; `(builtin root, prototype link)`.
    let (builtin_root, prototype_link) = match it.left.as_simple_assignment_target() {
        Some(oxc_ast::ast::SimpleAssignmentTarget::StaticMemberExpression(member)) => {
            member_builtin_conflict(&member.object)
        }
        Some(oxc_ast::ast::SimpleAssignmentTarget::ComputedMemberExpression(member)) => {
            member_builtin_conflict(&member.object)
        }
        _ => (false, false),
    };
    if builtin_root || prototype_link {
        sink.emit_span(
            RuleScope::Both,
            "S2424",
            "Do not modify built-in objects.",
            it.left.span(),
        );
    }
    if prototype_link {
        sink.emit_span(
            RuleScope::Both,
            "S6643",
            "Do not extend built-in prototypes.",
            it.left.span(),
        );
    }
}

/// Walks a member chain: is its root a built-in global (or `prototype`),
/// and does any link assign through `.prototype`?
fn member_builtin_conflict(expression: &Expression<'_>) -> (bool, bool) {
    match expression {
        Expression::Identifier(identifier) => {
            let name = identifier.name.as_ref();
            (
                BUILTIN_GLOBALS.contains(&name) || name == "prototype",
                false,
            )
        }
        Expression::StaticMemberExpression(member) => {
            let (root, prototype) = member_builtin_conflict(&member.object);
            (root, prototype || member.property.name == "prototype")
        }
        Expression::ComputedMemberExpression(member) => member_builtin_conflict(&member.object),
        _ => (false, false),
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s2424_flags_builtin_writes_and_sign_swap_typo() {
        let findings = js_keys("Array.prototype.custom = 1;\nx =+ 1;\n");
        assert_eq!(count_key(&findings, "javascript:S2424"), 1);
        assert_eq!(count_key(&findings, "javascript:S6643"), 1);
        assert_eq!(count_key(&findings, "javascript:S2757"), 1);
    }

    #[test]
    fn s2424_allows_plain_targets_and_compound_assignment() {
        let findings = js_keys("obj.prop = 1;\nx += 1;\ny = 1 - 2;\nz = +1;\n");
        assert_eq!(count_key(&findings, "javascript:S2424"), 0);
        assert_eq!(count_key(&findings, "javascript:S2757"), 0);
    }

    #[test]
    fn s2757_requires_adjacent_assignment_and_separated_unary_operators() {
        let clean = js_keys("x =\u{00a0}+1;\nx =+1;\n");
        assert_eq!(count_key(&clean, "javascript:S2757"), 0);

        let report = js("x =+ 1;\n");
        let finding = report
            .issues
            .iter()
            .find(|issue| issue.rule_key.ends_with(":S2757"))
            .expect("sign-swap finding");
        assert_eq!(finding.range.start.column, 2);
        assert_eq!(finding.range.end.column, 4);
    }

    #[test]
    fn s2757_ignores_comparison_and_compound_assignment_unaries() {
        let findings = js_keys("let comparison = x ==+ 1;\nlet compound = x +=+ 1;\n");
        assert_eq!(count_key(&findings, "javascript:S2757"), 0);
    }

    #[test]
    fn s2424_builtin_root_without_prototype_skips_extension_rule() {
        let findings = js_keys("Math.pi = 3;\n");
        assert_eq!(count_key(&findings, "javascript:S2424"), 1);
        assert_eq!(count_key(&findings, "javascript:S6643"), 0);
    }
}
