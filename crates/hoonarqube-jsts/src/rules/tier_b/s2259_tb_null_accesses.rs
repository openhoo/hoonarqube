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
            &format!("TypeError can be thrown as \"{kind}\" might be null or undefined here."),
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
        assert_eq!(filtered(&js("undefined.bar;\n"), "S2259").len(), 1);
        assert_eq!(filtered(&js("null.foo();\n"), "S2259").len(), 0);
        assert_eq!(filtered(&js("value(null.x);\n"), "S2259").len(), 0);
        assert_eq!(filtered(&ts("undefined.bar;\n"), "S2259").len(), 0);
        assert_eq!(filtered(&js("null?.foo;\n"), "S2259").len(), 0);
    }
}
