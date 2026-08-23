// Rule module s2589_tb_constant_conditions (generated).
use crate::support::{IssueSink, RuleScope};
use oxc_ast_visit::Visit;
use oxc_span::Span;

/// `S2589`: conditions that are literal booleans.
pub(crate) fn check_tb_constant_conditions(
    program: &oxc_ast::ast::Program<'_>,
    sink: &mut IssueSink<'_>,
) {
    let mut collector = ConstantConditionCollector::default();
    collector.visit_program(program);
    for (span, value) in collector.sites {
        sink.emit_span(
            RuleScope::Both,
            "S2589",
            &format!("This condition always evaluates to {value}; consider removing it."),
            span,
        );
    }
}

/// Collects literal boolean conditions (`S2589`).
#[derive(Default)]
pub(crate) struct ConstantConditionCollector {
    pub(crate) sites: Vec<(Span, bool)>,
}
