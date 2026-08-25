// Family walker for 'swapped_call_arguments' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::engine::scope_model::FunctionParamMapCollector;
use crate::rules::shared::argument_expression;
use crate::support::{IssueSink, LineIndex, RuleScope, callee_name, identifier_name};
use hoonarqube_ir::Issue;
use oxc_ast::ast::CallExpression;
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::walk_call_expression;
use oxc_span::GetSpan;
use std::collections::BTreeMap;

fn check_swapped_call_arguments(
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
struct CallArgumentOrderCollector<'index> {
    sink: IssueSink<'index>,
    params_by_name: BTreeMap<String, Vec<String>>,
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

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn swapped_call_arguments_detected_by_name_match() {
        let source = "\
function draw(width, height) {}
draw(height, width);
draw(width, height);
draw(other, more);
";
        let report = js(source);
        let s2234_lines: Vec<u32> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S2234"))
            .map(|issue| issue.range.start.line)
            .collect();
        assert_eq!(s2234_lines, vec![2]);
    }

    #[test]
    fn s2234_requires_known_callee_matching_arity_and_names() {
        // Unknown callees are never checked.
        assert_eq!(
            count_key(
                &js_keys("function draw(width, height) {}\nunknown(width, height);\n"),
                "javascript:S2234"
            ),
            0
        );
        // Arity mismatch with the signature skips the check.
        assert_eq!(
            count_key(
                &js_keys("function draw(width, height) {}\ndraw(height, width, extra);\n"),
                "javascript:S2234"
            ),
            0
        );
        // A non-identifier argument blocks the name-based comparison.
        assert_eq!(
            count_key(
                &js_keys("function draw(width, height) {}\ndraw(height, f());\n"),
                "javascript:S2234"
            ),
            0
        );
    }

    #[test]
    fn s2234_detects_swap_among_three_arguments() {
        assert_eq!(
            count_key(
                &js_keys("function scale(a, b, c) {}\nscale(b, a, c);\n"),
                "javascript:S2234"
            ),
            1
        );
    }
}
