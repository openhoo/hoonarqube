// Rule module s2424_assignment_rules (generated).
use super::s1442_plain_calls::BUILTIN_GLOBALS;
use crate::support::{IssueSink, RuleScope};
use oxc_ast::ast::{AssignmentExpression, AssignmentOperator, Expression, UnaryOperator};
use oxc_span::GetSpan;

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
            "Swap the \"=\" and sign characters if a compound assignment was intended.",
            it.right.span(),
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
pub(crate) fn member_builtin_conflict(expression: &Expression<'_>) -> (bool, bool) {
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
