// Residual rule machinery for 'batch2d' (extracted from lib.rs).
use crate::rules::batch2d::s3512_es_idioms::EsIdiomCollector;
use crate::rules::shared::argument_expression;
use crate::rules::shared::call_property;
use crate::support::RuleScope;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Expression;
use oxc_ast::ast::RegExpFlags;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl EsIdiomCollector<'_> {
    /// `S6594` logic extracted from `visit_call_expression`.
    pub(crate) fn check_s6594_call_expression(&mut self, it: &CallExpression<'_>) {
        // `S6594`: `.match(/…/g)` prefers `.matchAll` or `.exec`.
        if let Some((property, _member)) = call_property(it)
            && property == "match"
            && let Some(argument) = it.arguments.first().and_then(argument_expression)
            && let Expression::RegExpLiteral(literal) = argument
            && literal.regex.flags.contains(RegExpFlags::G)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6594",
                "Prefer \".matchAll\" or \".exec\" over \".match\" for this global regex.",
                it.span(),
            );
        }
    }
}
