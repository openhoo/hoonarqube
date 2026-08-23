// Rule module s4784_tb_dynamic_regexps (generated).
use crate::support::{IssueSink, RuleScope};
use oxc_ast_visit::Visit;
use oxc_span::Span;
use std::collections::HashSet;

/// `S4784`: regular expressions built from non-static sources.
pub(crate) fn check_tb_dynamic_regexps(
    program: &oxc_ast::ast::Program<'_>,
    sink: &mut IssueSink<'_>,
) {
    let mut collector = DynamicRegexCollector::default();
    collector.visit_program(program);
    for span in collector.sites {
        sink.emit_span(
            RuleScope::Both,
            "S4784",
            "Do not build this regular expression dynamically; use a static pattern.",
            span,
        );
    }
    for (span, name) in collector.unresolved {
        let statically_bound =
            collector.static_bindings.contains(name) && !collector.dynamic_bindings.contains(name);
        if !statically_bound {
            sink.emit_span(
                RuleScope::Both,
                "S4784",
                "Do not build this regular expression dynamically; use a static pattern.",
                span,
            );
        }
    }
}

/// Dynamically built `new RegExp(...)` patterns (`S4784`).
#[derive(Default)]
pub(crate) struct DynamicRegexCollector<'p> {
    pub(crate) sites: Vec<Span>,
    /// Identifier arguments awaiting binding resolution: `(new span, name)`.
    pub(crate) unresolved: Vec<(Span, &'p str)>,
    pub(crate) static_bindings: HashSet<&'p str>,
    pub(crate) dynamic_bindings: HashSet<&'p str>,
}
