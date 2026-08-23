// Rule module s2259_tb_null_accesses (generated).
use crate::support::{IssueSink, RuleScope};
use oxc_ast_visit::Visit;
use oxc_span::Span;

/// `S2259` (JavaScript only): property access on `null`/`undefined`.
pub(crate) fn check_tb_null_accesses(
    program: &oxc_ast::ast::Program<'_>,
    sink: &mut IssueSink<'_>,
    undefined_shadowed: bool,
) {
    let mut collector = NullAccessCollector {
        undefined_shadowed,
        sites: Vec::new(),
    };
    collector.visit_program(program);
    for (kind, span) in collector.sites {
        sink.emit_span(
            RuleScope::JsOnly,
            "S2259",
            &format!("This property access on '{kind}' will throw a TypeError."),
            span,
        );
    }
}

/// Member accesses whose base is `null`/`undefined` (`S2259`).
#[derive(Default)]
pub(crate) struct NullAccessCollector {
    pub(crate) sites: Vec<(&'static str, Span)>,
    pub(crate) undefined_shadowed: bool,
}
