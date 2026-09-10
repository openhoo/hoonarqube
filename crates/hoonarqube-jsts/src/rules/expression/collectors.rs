// Residual rule machinery for 'expression' (extracted from lib.rs).
use crate::rules::shared::CONSOLE_METHODS;
use crate::rules::shared::argument_expression;
use crate::support::{
    IssueSink, RuleScope, member_object, member_root_name, member_rooted_at, unparenthesized,
};
use oxc_ast::ast::{CallExpression, Expression, Function, MemberExpression, ThisExpression};
use oxc_ast_visit::Visit;
use oxc_span::GetSpan;
use oxc_syntax::scope::ScopeFlags;

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
            "Unexpected console statement.",
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
        && argument_expression(&it.arguments[0]).is_some()
        && bind_target_is_unnecessary(member_object(member))
    {
        let span = match member {
            MemberExpression::StaticMemberExpression(member) => member.property.span(),
            _ => it.callee.span(),
        };
        sink.emit_span(
            RuleScope::Both,
            "S6637",
            "The function binding is unnecessary.",
            span,
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
        let span = match member {
            MemberExpression::StaticMemberExpression(member) => member.property.span(),
            _ => it.callee.span(),
        };
        sink.emit_span(
            RuleScope::Both,
            "S2871",
            "Provide a compare function to avoid sorting elements alphabetically.",
            span,
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
            "Avoid arguments.callee.",
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

/// Whether the `.bind(...)` receiver is a function whose own `this` is not
/// needed. Arrow functions never own `this`; ordinary functions do unless
/// their body (excluding nested ordinary functions) uses it.
fn bind_target_is_unnecessary(expression: &Expression<'_>) -> bool {
    match unparenthesized(expression) {
        Expression::ArrowFunctionExpression(_) => true,
        Expression::FunctionExpression(function) => !function_uses_this(function),
        _ => false,
    }
}

fn function_uses_this(function: &Function<'_>) -> bool {
    let mut collector = ThisUsageCollector::default();
    collector.visit_formal_parameters(&function.params);
    if let Some(body) = function.body.as_deref() {
        collector.visit_function_body(body);
    }
    collector.found_this
}

#[derive(Default)]
struct ThisUsageCollector {
    found_this: bool,
}

impl<'a> Visit<'a> for ThisUsageCollector {
    fn visit_this_expression(&mut self, _: &ThisExpression) {
        self.found_this = true;
    }

    // A nested ordinary function has its own `this`, so it must not make the
    // enclosing function appear to use its receiver.
    fn visit_function(&mut self, _: &Function<'a>, _: ScopeFlags) {}
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6637_flags_arrow_and_plain_functions_without_this() {
        let findings = js_keys(
            "const arrow = (() => 1).bind(receiver);\n\
             const plain = function () {}.bind(receiver);\n",
        );
        assert_eq!(count_key(&findings, "javascript:S6637"), 2);
    }

    #[test]
    fn s6637_preserves_outer_this_and_meaningful_arguments() {
        let findings = js_keys(
            "const uses = function () { return this.value; }.bind(receiver);\n\
             const nested_arrow = function () { return () => this.value; }.bind(receiver);\n\
             const nested_function = function () { return function () { return this.value; }; }.bind(receiver);\n\
             const extra_args = function () {}.bind(receiver, value);\n\
             const spread = function () {}.bind(...values);\n",
        );
        // The nested ordinary function owns its own `this`; only the outer
        // binding is unnecessary in that case.
        assert_eq!(count_key(&findings, "javascript:S6637"), 1);
    }

    #[test]
    fn s6637_keeps_the_legacy_good_fixture_as_positive_evidence() {
        let findings = js_keys("const f = function () {}.bind(this);\n");
        assert_eq!(count_key(&findings, "javascript:S6637"), 1);
    }
}
