// Residual rule machinery for 'batch2d' (extracted from lib.rs).
use crate::rules::batch2d::s3512_es_idioms::EsIdiomCollector;
use crate::support::RuleScope;
use crate::support::unparenthesized;
use oxc_ast::ast::ConditionalExpression;
use oxc_ast::ast::Expression;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl EsIdiomCollector<'_> {
    /// `S3358` logic extracted from `visit_conditional_expression`.
    pub(crate) fn check_s3358_conditional_expression(&mut self, it: &ConditionalExpression<'_>) {
        // `S3358`: ternaries nested in consequent or alternate positions.
        for branch in [&it.consequent, &it.alternate] {
            if let Expression::ConditionalExpression(nested) = unparenthesized(branch) {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S3358",
                    "Extract this nested ternary operation into an independent statement.",
                    nested.span(),
                );
            }
        }
    }
}
