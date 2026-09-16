// Rule module s2933_tb_readonly_candidate_fields (generated).
use crate::support::{IssueSink, RuleScope};
use oxc_ast_visit::Visit;
use oxc_span::Span;

/// `S2933` (TypeScript only): private fields written only at their
/// declaration initializer or inside the constructor become readonly.
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
            "This field is never reassigned after initialization; declare it 'readonly'.",
            span,
        );
    }
}

/// Private class fields written only at declaration or in the constructor
/// (`S2933`, TS only). The stack entry is `(name, key span, initialized)`.
#[derive(Default)]
pub(crate) struct ReadonlyFieldCollector<'p> {
    pub(crate) stack: Vec<Vec<(&'p str, Span, bool)>>,
    pub(crate) findings: Vec<Span>,
    pub(crate) writes: Vec<(&'p str, Span, bool)>,
    pub(crate) constructor_depth: u32,
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn constructor_only_fields_suggested_readonly_in_typescript() {
        let source =
            "class C {\n  private name;\n  constructor(value) {\n    this.name = value;\n  }\n}\n";
        assert_eq!(filtered(&ts(source), "S2933").len(), 1);
        assert_eq!(filtered(&js(source), "S2933").len(), 0);
        let method_written =
            "class C {\n  private count;\n  tick() {\n    this.count = 1;\n  }\n}\n";
        assert_eq!(filtered(&ts(method_written), "S2933").len(), 0);
        let already_readonly =
            "class C {\n  private readonly id;\n  constructor() {\n    this.id = 1;\n  }\n}\n";
        assert_eq!(filtered(&ts(already_readonly), "S2933").len(), 0);
        let initialized =
            "class C {\n  private preset = 1;\n  constructor() {\n    this.preset = 2;\n  }\n}\n";
        assert_eq!(filtered(&ts(initialized), "S2933").len(), 1);
    }

    #[test]
    fn declaration_initialized_private_fields_flagged() {
        // #477: `prefer-readonly` also covers fields initialized at the
        // declaration and never reassigned.
        let source = "class C {\n  private cache = new Map();\n  get(k) {\n    return this.cache.get(k);\n  }\n}\n";
        assert_eq!(filtered(&ts(source), "S2933").len(), 1);
        let hash_private =
            "class C {\n  #state = 0;\n  read() {\n    return this.#state;\n  }\n}\n";
        assert_eq!(filtered(&ts(hash_private), "S2933").len(), 1);
    }

    #[test]
    fn non_private_fields_stay_silent() {
        // #478: `prefer-readonly` never considers public or protected
        // fields, whatever their assignment pattern.
        let source = "class C {\n  parent;\n  view;\n  protected index;\n  constructor(v, i, p) {\n    this.view = v;\n    this.index = i;\n    this.parent = p;\n  }\n}\n";
        assert_eq!(filtered(&ts(source), "S2933").len(), 0);
        let never_written = "class C {\n  private untouched;\n}\n";
        assert_eq!(filtered(&ts(never_written), "S2933").len(), 0);
    }
}
