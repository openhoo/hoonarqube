// Residual rule machinery for 'batch2d' (extracted from lib.rs).
use crate::rules::batch2d::s3512_es_idioms::EsIdiomCollector;
use crate::support::RuleScope;
use crate::support::ast::constructor_name;
use oxc_ast::ast::NewExpression;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl EsIdiomCollector<'_> {
    /// `S3523` logic extracted from `visit_new_expression`.
    pub(crate) fn check_s3523_new_expression(&mut self, it: &NewExpression<'_>) {
        // `S3523`: the `Function` constructor (JavaScript-only); overlaps
        // the `S1523` finding on purpose — separate catalog rule keys.
        if constructor_name(it) == Some("Function") {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S3523",
                "Remove this use of the \"Function\" constructor.",
                it.callee.span(),
            );
        }
    }
}
