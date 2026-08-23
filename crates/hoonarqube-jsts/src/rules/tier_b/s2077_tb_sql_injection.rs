// Rule module s2077_tb_sql_injection (generated).
use crate::support::{IssueSink, RuleScope};
use oxc_ast_visit::Visit;
use oxc_span::Span;

/// `S2077`: SQL sinks fed interpolated or concatenated strings.
pub(crate) fn check_tb_sql_injection(
    program: &oxc_ast::ast::Program<'_>,
    sink: &mut IssueSink<'_>,
) {
    let mut collector = SqlInjectionCollector::default();
    collector.visit_program(program);
    for span in collector.sites {
        sink.emit_span(
            RuleScope::Both,
            "S2077",
            "Use parameterized queries instead of building SQL with interpolation.",
            span,
        );
    }
}

/// Collects SQL sink calls receiving dynamically built strings (`S2077`).
#[derive(Default)]
pub(crate) struct SqlInjectionCollector {
    pub(crate) sites: Vec<Span>,
}
