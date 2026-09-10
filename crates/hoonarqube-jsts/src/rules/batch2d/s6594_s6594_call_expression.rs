// Residual rule machinery for 'batch2d' (extracted from lib.rs).
use crate::rules::batch2d::s3512_es_idioms::EsIdiomCollector;
use crate::rules::shared::argument_expression;
use crate::rules::shared::call_property;
use crate::support::{RuleScope, unparenthesized};
use oxc_ast::ast::{CallExpression, Expression, RegExpFlags};
use oxc_span::Span;

impl EsIdiomCollector<'_> {
    /// `S6594` logic extracted from `visit_call_expression`.
    ///
    /// The native detector deliberately keeps the upstream syntax gate broad:
    /// type information is unavailable here, so the semantic String receiver
    /// proof belongs to the quick-fix collector. This preserves findings for
    /// unresolved receivers while never attaching an unsafe edit.
    pub(crate) fn check_s6594_call_expression(&mut self, it: &CallExpression<'_>) {
        let Some((property, member)) = call_property(it) else {
            return;
        };
        if property != "match" || it.arguments.len() != 1 {
            return;
        }
        let Some(argument) = it.arguments.first().and_then(argument_expression) else {
            return;
        };
        let Expression::RegExpLiteral(literal) = unparenthesized(argument) else {
            return;
        };
        if literal.regex.flags.contains(RegExpFlags::G) {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S6594",
            "Use the \"RegExp.exec()\" method instead.",
            member_property_span(member),
        );
    }
}

fn member_property_span(member: &oxc_ast::ast::MemberExpression<'_>) -> Span {
    match member {
        oxc_ast::ast::MemberExpression::StaticMemberExpression(member) => member.property.span,
        _ => Span::sized(0, 0),
    }
}
