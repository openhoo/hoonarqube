// Family walker for 'call_argument_lines' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::rules::expression::s1528_constructor_calls::argument_expression;
use crate::support::{IssueSink, LineIndex, RuleScope};
use hoonarqube_ir::Issue;
use oxc_ast::ast::CallExpression;
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::walk_call_expression;
use oxc_span::GetSpan;

pub(crate) fn check_call_argument_lines(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = CallArgumentCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// `S1472`: calls whose first argument starts on a later line than the call.
pub(crate) struct CallArgumentCollector<'index> {
    pub(crate) sink: IssueSink<'index>,
}

impl<'a> Visit<'a> for CallArgumentCollector<'_> {
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        if let Some(first) = it.arguments.first().and_then(argument_expression) {
            let call_line = self.sink.index.pos(it.span.start).line;
            let argument_line = self.sink.index.pos(first.span().start).line;
            if call_line != argument_line {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1472",
                    "Move the arguments of this call onto the same line as the call.",
                    first.span(),
                );
            }
        }
        walk_call_expression(self, it);
    }
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_call_argument_lines(ctx.program, ctx.index, ctx.language)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn call_arguments_split_across_lines_are_flagged() {
        let split = js("foo(\n  bar);\n");
        let s1472: Vec<_> = split
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S1472"))
            .collect();
        assert_eq!(s1472.len(), 1);
        assert_eq!(
            s1472[0].range,
            hoonarqube_ir::Range {
                start: pos(2, 2),
                end: pos(2, 5),
            }
        );

        assert_eq!(count_key(&js_keys("foo(bar);\n"), "javascript:S1472"), 0);
    }

    #[test]
    fn s1472_ignores_spread_first_arguments_and_empty_calls() {
        assert_eq!(
            count_key(&js_keys("foo(\n  ...args);\n"), "javascript:S1472"),
            0
        );
        assert_eq!(count_key(&js_keys("foo();\n"), "javascript:S1472"), 0);
    }

    #[test]
    fn s1472_flags_each_call_with_first_argument_on_next_line() {
        // Only the inner call's first argument starts on a later line.
        assert_eq!(
            count_key(&js_keys("outer(inner(\n  1));\n"), "javascript:S1472"),
            1
        );
        assert_eq!(
            count_key(&js_keys("foo(\n  a,\n  b);\n"), "javascript:S1472"),
            1
        );
    }
}
