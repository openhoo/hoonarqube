use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::support::RuleScope;
use oxc_ast::ast::TemplateLiteral;
use oxc_span::Span;

impl SecurityHotspotCollector<'_, '_> {
    /// `S6299`: `v-html` usages inside template strings worth reviewing.
    pub(crate) fn check_vue_v_html_string(&mut self, value: &str, span: Span) {
        if value.contains("v-html") {
            self.sink.emit_span(
                RuleScope::Both,
                "S6299",
                "Make sure disabling Vue.js built-in escaping with 'v-html' is safe here.",
                span,
            );
        }
    }

    /// `S6299`: `v-html` usages inside template literals.
    pub(crate) fn check_vue_v_html_template(&mut self, literal: &TemplateLiteral<'_>) {
        if literal
            .quasis
            .iter()
            .any(|element| element.value.raw.contains("v-html"))
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6299",
                "Make sure disabling Vue.js built-in escaping with 'v-html' is safe here.",
                literal.span,
            );
        }
    }
}
