// Residual rule machinery for 'batch2d' (extracted from lib.rs).
use crate::rules::batch2d::s3512_es_idioms::EsIdiomCollector;
use crate::support::RuleScope;
use crate::support::member_object;
use crate::support::unparenthesized;
use oxc_ast::ast::Expression;
use oxc_ast::ast::MemberExpression;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl EsIdiomCollector<'_> {
    /// `S4158` logic extracted from `visit_member_expression`.
    pub(crate) fn check_s4158_member_expression(&mut self, it: &MemberExpression<'_>) {
        // `S4158`: operations on empty array literals always do nothing.
        if matches!(
            unparenthesized(member_object(it)),
            Expression::ArrayExpression(array) if array.elements.is_empty()
        ) {
            self.sink.emit_span(
                RuleScope::Both,
                "S4158",
                "Review this operation; it always targets an empty array.",
                it.span(),
            );
        }
    }
}
