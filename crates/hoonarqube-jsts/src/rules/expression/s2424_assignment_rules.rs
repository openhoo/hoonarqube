// Rule module s2424_assignment_rules (generated).
use super::s1442_plain_calls::BUILTIN_GLOBALS;
use crate::support::{IssueSink, RuleScope};
use oxc_ast::ast::{AssignmentExpression, AssignmentOperator, Expression, UnaryOperator};
use oxc_span::{GetSpan, Span};

/// `S2757` (the `x =+ 1` typo), `S6643`/`S2424` (writes into built-ins).
pub(crate) fn check_assignment_rules(sink: &mut IssueSink, it: &AssignmentExpression<'_>) {
    if it.operator == AssignmentOperator::Assign
        && let Expression::UnaryExpression(unary) = &it.right
        && matches!(
            unary.operator,
            UnaryOperator::UnaryPlus | UnaryOperator::UnaryNegation
        )
    {
        sink.emit_span(
            RuleScope::Both,
            "S2757",
            &format!(
                "Was \"{}=\" meant instead?",
                if unary.operator == UnaryOperator::UnaryPlus {
                    "+"
                } else {
                    "-"
                }
            ),
            Span::new(unary.span.start.saturating_sub(1), unary.span.start + 1),
        );
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
        let findings = js_keys("obj.prop = 1;\nx += 1;\ny = 1 - 2;\n");
        assert_eq!(count_key(&findings, "javascript:S2424"), 0);
        assert_eq!(count_key(&findings, "javascript:S2757"), 0);
    }

    #[test]
    fn s2424_builtin_root_without_prototype_skips_extension_rule() {
        let findings = js_keys("Math.pi = 3;\n");
        assert_eq!(count_key(&findings, "javascript:S2424"), 1);
        assert_eq!(count_key(&findings, "javascript:S6643"), 0);
    }
}
