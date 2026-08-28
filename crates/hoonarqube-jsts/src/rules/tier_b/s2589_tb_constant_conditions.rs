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
        if !value {
            continue;
        }
        sink.emit_span(
            RuleScope::Both,
            "S2589",
            "This always evaluates to truthy. Consider refactoring this code.",
            span,
        );
    }
}

/// Collects literal boolean conditions (`S2589`).
#[derive(Default)]
pub(crate) struct ConstantConditionCollector {
    pub(crate) sites: Vec<(Span, bool)>,
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn constant_boolean_conditions_flagged() {
        let flagged = js("if (true) {\n  work();\n}\nwhile (false) {\n  skip();\n}\n");
        assert_eq!(filtered(&flagged, "S2589").len(), 1);
        let clean = js("if (cond) {\n  work();\n}\nwhile (running) {\n  skip();\n}\n");
        assert_eq!(filtered(&clean, "S2589").len(), 0);
    }
}
