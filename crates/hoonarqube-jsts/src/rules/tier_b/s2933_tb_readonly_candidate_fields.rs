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

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn constructor_only_fields_suggested_readonly_in_typescript() {
        let source = "class C {\n  name;\n  constructor(value) {\n    this.name = value;\n  }\n}\n";
        assert_eq!(filtered(&ts(source), "S2933").len(), 1);
        assert_eq!(filtered(&js(source), "S2933").len(), 0);
        let method_written = "class C {\n  count;\n  tick() {\n    this.count = 1;\n  }\n}\n";
        assert_eq!(filtered(&ts(method_written), "S2933").len(), 0);
        let already_readonly =
            "class C {\n  readonly id;\n  constructor() {\n    this.id = 1;\n  }\n}\n";
        assert_eq!(filtered(&ts(already_readonly), "S2933").len(), 0);
        let initialized =
            "class C {\n  preset = 1;\n  constructor() {\n    this.preset = 2;\n  }\n}\n";
        assert_eq!(filtered(&ts(initialized), "S2933").len(), 0);
    }
}
