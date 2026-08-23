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
