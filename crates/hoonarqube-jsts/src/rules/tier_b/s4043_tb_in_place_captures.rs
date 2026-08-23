// Rule module s4043_tb_in_place_captures (generated).
use crate::support::{IssueSink, RuleScope};
use oxc_ast_visit::Visit;
use oxc_span::Span;

/// `S4043`: in-place method result captured while the original is reused.
pub(crate) fn check_tb_in_place_captures(
    program: &oxc_ast::ast::Program<'_>,
    sink: &mut IssueSink<'_>,
) {
    let mut collector = InPlaceCaptureCollector::default();
    collector.visit_program(program);
    for (base_name, method, call_span) in &collector.captures {
        let original_reused_later = collector
            .references
            .iter()
            .any(|(name, span)| *name == *base_name && span.start > call_span.end);
        if original_reused_later {
            sink.emit_span(
                RuleScope::Both,
                "S4043",
                &format!(
                    "'{method}()' mutates '{base_name}' in place; the captured value aliases it."
                ),
                *call_span,
            );
        }
    }
}

/// Captured results of in-place array methods whose base is reused (`S4043`).
#[derive(Default)]
pub(crate) struct InPlaceCaptureCollector<'p> {
    /// `(base name, method, call span)` of captured in-place calls.
    pub(crate) captures: Vec<(&'p str, &'p str, Span)>,
    pub(crate) references: Vec<(&'p str, Span)>,
}
