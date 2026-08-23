// Family walker for 'swapped_call_arguments' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::engine::scope_model::FunctionParamMapCollector;
use crate::rules::expression::s1528_constructor_calls::argument_expression;
use crate::support::{IssueSink, LineIndex, RuleScope, callee_name, identifier_name};
use hoonarqube_ir::Issue;
use oxc_ast::ast::CallExpression;
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::walk_call_expression;
use oxc_span::GetSpan;
use std::collections::BTreeMap;

pub(crate) fn check_swapped_call_arguments(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut map_collector = FunctionParamMapCollector::default();
    map_collector.visit_program(program);
    let mut collector = CallArgumentOrderCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        params_by_name: map_collector.params_by_name,
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// `S2234`: calls of same-file functions where one adjacent swap increases
/// the number of argument names matching parameter names.
pub(crate) struct CallArgumentOrderCollector<'index> {
    pub(crate) sink: IssueSink<'index>,
    pub(crate) params_by_name: BTreeMap<String, Vec<String>>,
}

impl<'a> Visit<'a> for CallArgumentOrderCollector<'_> {
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        let mut checked_callee = false;
        if let Some(callee) = callee_name(it)
            && let Some(parameters) = self.params_by_name.get(callee)
        {
            checked_callee = true;
            let argument_names: Vec<Option<&str>> = it
                .arguments
                .iter()
                .map(|argument| argument_expression(argument).and_then(identifier_name))
                .collect();
            let count = argument_names.len();
            if count >= 2 && count == parameters.len() && argument_names.iter().all(Option::is_some)
            {
                let matched = |order: &[usize]| -> usize {
                    order
                        .iter()
                        .enumerate()
                        .filter(|(position, argument)| {
                            argument_names[**argument] == Some(parameters[*position].as_str())
                        })
                        .count()
                };
                let identity: Vec<usize> = (0..count).collect();
                let baseline = matched(&identity);
                let improved = (0..count - 1).any(|position| {
                    let mut swapped = identity.clone();
                    swapped.swap(position, position + 1);
                    matched(&swapped) > baseline
                });
                if improved {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S2234",
                        "Check this argument order; the arguments look swapped.",
                        it.span(),
                    );
                }
            }
        }
        if !checked_callee {
            walk_call_expression(self, it);
        }
    }
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_swapped_call_arguments(ctx.program, ctx.index, ctx.language)
}
