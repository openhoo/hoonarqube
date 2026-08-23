// Rule module s5876_tb_session_regeneration (generated).
use crate::support::{IssueSink, RuleScope, span_text_contains};
use oxc_ast_visit::Visit;
use oxc_span::Span;

/// `S5876`: login handlers that keep the pre-authentication session.
pub(crate) fn check_tb_session_regeneration(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    sink: &mut IssueSink<'_>,
) {
    let mut collector = SessionRegenerationCollector::default();
    collector.visit_program(program);
    for handler_span in collector.sites {
        let touches_session = span_text_contains(source, handler_span, "session");
        let regenerates = span_text_contains(source, handler_span, ".regenerate(");
        if touches_session && !regenerates {
            sink.emit_span(
                RuleScope::Both,
                "S5876",
                "Regenerate the session after login to prevent session fixation.",
                handler_span,
            );
        }
    }
}

// ===== Tier B remainder group 3: CFG-lite checks =====

/// Login endpoints whose handler never regenerates the session (`S5876`).
#[derive(Default)]
pub(crate) struct SessionRegenerationCollector {
    pub(crate) sites: Vec<Span>,
}
