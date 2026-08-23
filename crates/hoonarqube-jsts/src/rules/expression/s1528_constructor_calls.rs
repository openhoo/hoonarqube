// Rule module s1528_constructor_calls (generated).
use crate::support::{IssueSink, RuleScope, constructor_name};
use oxc_ast::ast::{Expression, NewExpression};
use oxc_span::GetSpan;

/// Constructor-call rules: `S1528`, `S1533`, `S2428`, and `S3834`.
pub(crate) fn check_constructor_calls(sink: &mut IssueSink, it: &NewExpression<'_>) {
    let Some(name) = constructor_name(it) else {
        return;
    };
    if name == "Array"
        && (it.arguments.len() >= 2
            || it.arguments.first().is_none_or(|argument| {
                argument_expression(argument)
                    .is_none_or(|expression| !matches!(expression, Expression::NumericLiteral(_)))
            }))
    {
        sink.emit_span(
            RuleScope::Both,
            "S1528",
            "Use array literal notation instead of the \"Array\" constructor.",
            it.span(),
        );
    }
    if matches!(name, "Number" | "String" | "Boolean") {
        sink.emit_span(
            RuleScope::Both,
            "S1533",
            "Use primitives instead of wrapper objects.",
            it.callee.span(),
        );
    }
    if name == "Object" {
        sink.emit_span(
            RuleScope::JsOnly,
            "S2428",
            "Use an object literal instead of \"new Object()\".",
            it.callee.span(),
        );
    }
    if matches!(name, "Symbol" | "BigInt") {
        sink.emit_span(
            RuleScope::JsOnly,
            "S3834",
            "Do not call this primitive constructor with \"new\".",
            it.callee.span(),
        );
    }
}

pub(crate) fn argument_expression<'r, 'a>(
    argument: &'r oxc_ast::ast::Argument<'a>,
) -> Option<&'r Expression<'a>> {
    argument.as_expression()
}
