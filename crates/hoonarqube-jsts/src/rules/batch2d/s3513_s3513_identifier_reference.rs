// Residual rule machinery for 'batch2d' (extracted from lib.rs).
use crate::rules::batch2d::s3512_es_idioms::EsIdiomCollector;
use crate::support::RuleScope;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl EsIdiomCollector<'_> {
    /// `S3513` logic extracted from `visit_identifier_reference`.
    pub(crate) fn check_s3513_identifier_reference(
        &mut self,
        it: &oxc_ast::ast::IdentifierReference<'_>,
    ) {
        // `S3513`: direct `arguments` reads where no parameter shadows it.
        if it.name == "arguments" && !self.arguments_shadowed.iter().any(|&shadowed| shadowed) {
            self.sink.emit_span(
                RuleScope::Both,
                "S3513",
                "Use rest parameters instead of \"arguments\".",
                it.span(),
            );
        }
    }
}
