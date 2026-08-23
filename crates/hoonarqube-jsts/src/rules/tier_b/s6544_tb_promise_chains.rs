// Rule module s6544_tb_promise_chains (generated).
use crate::support::{IssueSink, RuleScope};
use oxc_ast_visit::Visit;
use oxc_span::Span;

/// `S6544`: value-less `.then()` callbacks inside longer chains.
pub(crate) fn check_tb_promise_chains(
    program: &oxc_ast::ast::Program<'_>,
    sink: &mut IssueSink<'_>,
) {
    let mut collector = PromiseChainCollector::default();
    collector.visit_program(program);
    for span in collector.sites {
        sink.emit_span(
            RuleScope::Both,
            "S6544",
            "This '.then()' callback returns nothing although its result is chained further.",
            span,
        );
    }
}

/// `.then(callback)` results consumed without a returned value (`S6544`).
#[derive(Default)]
pub(crate) struct PromiseChainCollector {
    pub(crate) sites: Vec<Span>,
}
