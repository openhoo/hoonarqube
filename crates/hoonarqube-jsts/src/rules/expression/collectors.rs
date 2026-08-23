// Residual rule machinery for 'expression' (extracted from lib.rs).
use crate::rules::expression::s1528_constructor_calls::argument_expression;
use crate::support::{IssueSink, RuleScope, member_object, member_root_name, member_rooted_at};
use oxc_ast::ast::{CallExpression, Expression, MemberExpression};
use oxc_span::GetSpan;

/// `console` members flagged by `S106`.
pub(crate) const CONSOLE_METHODS: [&str; 8] = [
    "log", "info", "warn", "error", "debug", "trace", "dir", "table",
];

/// `S106`, `S1442`, `S6637`, and `S6676`.
pub(crate) fn check_logging_and_binding_calls(
    sink: &mut IssueSink,
    it: &CallExpression<'_>,
    property: &str,
    member: &MemberExpression<'_>,
) {
    if member_rooted_at(member, "console") && CONSOLE_METHODS.contains(&property) {
        sink.emit_span(
            RuleScope::Both,
            "S106",
            "Remove this console logging call.",
            it.callee.span(),
        );
    }
    if property == "alert" {
        sink.emit_span(
            RuleScope::JsOnly,
            "S1442",
            "Remove this use of \"alert\".",
            it.callee.span(),
        );
    }
    if property == "bind"
        && it.arguments.len() == 1
        && argument_expression(&it.arguments[0])
            .is_some_and(|argument| matches!(argument, Expression::ThisExpression(_)))
        && bind_target_is_arrow(member_object(member))
    {
        sink.emit_span(
            RuleScope::Both,
            "S6637",
            "Arrow functions are already bound; remove this \".bind(this)\".",
            it.callee.span(),
        );
    }
    if matches!(property, "call" | "apply") && it.arguments.len() == 1 {
        sink.emit_span(
            RuleScope::Both,
            "S6676",
            "Invoke this function directly instead of via \"call\"/\"apply\".",
            it.callee.span(),
        );
    }
}

/// `S6666`, `S6959`, `S2871`, `S6653`, `S2685`, `S6654`, and `S6661`.
pub(crate) fn check_collection_and_object_calls(
    sink: &mut IssueSink,
    it: &CallExpression<'_>,
    property: &str,
    member: &MemberExpression<'_>,
) {
    if property == "apply"
        && it.arguments.len() == 2
        && argument_expression(&it.arguments[1])
            .is_some_and(|argument| matches!(argument, Expression::ArrayExpression(_)))
    {
        sink.emit_span(
            RuleScope::Both,
            "S6666",
            "Use spread syntax instead of \"apply\".",
            it.arguments[1].span(),
        );
    }
    if property == "reduce" && it.arguments.len() == 1 {
        sink.emit_span(
            RuleScope::Both,
            "S6959",
            "Provide an initial accumulator value to this \"reduce\".",
            it.callee.span(),
        );
    }
    if matches!(property, "sort" | "toSorted") && it.arguments.is_empty() {
        sink.emit_span(
            RuleScope::Both,
            "S2871",
            "Provide a comparator to this sort call.",
            it.callee.span(),
        );
    }
    if property == "hasOwnProperty" {
        sink.emit_span(
            RuleScope::Both,
            "S6653",
            "Use \"Object.hasOwn()\" instead of \"hasOwnProperty()\".",
            it.callee.span(),
        );
    }
    if matches!(property, "caller" | "callee") && member_root_name(member) == Some("arguments") {
        sink.emit_span(
            RuleScope::Both,
            "S2685",
            "Do not access \"arguments.caller\"/\"arguments.callee\".",
            it.callee.span(),
        );
    }
    if property == "__proto__" {
        sink.emit_span(
            RuleScope::Both,
            "S6654",
            "Use \"Object.getPrototypeOf()\"/\"Object.setPrototypeOf()\" instead of \"__proto__\".",
            it.callee.span(),
        );
    }
    if property == "assign"
        && member_rooted_at(member, "Object")
        && it
            .arguments
            .first()
            .and_then(argument_expression)
            .is_some_and(|argument| matches!(argument, Expression::ObjectExpression(_)))
    {
        sink.emit_span(
            RuleScope::Both,
            "S6661",
            "Use object spread syntax instead of \"Object.assign\".",
            it.arguments[0].span(),
        );
    }
}

/// Whether the `.bind(this)` receiver is an arrow function, possibly inside
/// parentheses (`(() => 1).bind(this)`).
pub(crate) fn bind_target_is_arrow(expression: &Expression<'_>) -> bool {
    match expression {
        Expression::ArrowFunctionExpression(_) => true,
        Expression::ParenthesizedExpression(parenthesized) => {
            matches!(
                &parenthesized.expression,
                Expression::ArrowFunctionExpression(_)
            )
        }
        _ => false,
    }
}
