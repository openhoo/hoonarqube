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

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn null_member_access_is_javascript_only() {
        let sources = ["null.foo();\n", "undefined.bar;\n", "value(null.x);\n"];
        for source in sources {
            assert_eq!(filtered(&js(source), "S2259").len(), 1, "{source}");
            assert_eq!(filtered(&ts(source), "S2259").len(), 0, "{source}");
        }
        assert_eq!(filtered(&js("null?.foo;\n"), "S2259").len(), 0);
    }
}
