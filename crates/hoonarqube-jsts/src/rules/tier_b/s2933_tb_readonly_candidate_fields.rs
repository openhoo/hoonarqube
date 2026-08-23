// Rule module s2933_tb_readonly_candidate_fields (generated).
use crate::support::{IssueSink, RuleScope};
use oxc_ast_visit::Visit;
use oxc_span::Span;

/// `S2933` (TypeScript only): constructor-assigned fields become readonly.
pub(crate) fn check_tb_readonly_candidate_fields(
    program: &oxc_ast::ast::Program<'_>,
    sink: &mut IssueSink<'_>,
) {
    let mut collector = ReadonlyFieldCollector::default();
    collector.visit_program(program);
    for span in collector.findings {
        sink.emit_span(
            RuleScope::TsOnly,
            "S2933",
            "This field is assigned only in the constructor; declare it 'readonly'.",
            span,
        );
    }
}

/// Class fields assigned only inside constructors (`S2933`, TS only).
#[derive(Default)]
pub(crate) struct ReadonlyFieldCollector<'p> {
    pub(crate) stack: Vec<Vec<(&'p str, Span)>>,
    pub(crate) findings: Vec<Span>,
    pub(crate) writes: Vec<(&'p str, Span, bool)>,
    pub(crate) constructor_depth: u32,
}
