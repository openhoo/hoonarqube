//! S7743: immediately invoked arrows with parenthesized expression bodies.
use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{CallExpression, Expression};
use oxc_ast_visit::{Visit, walk::walk_call_expression};

pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut collector = IifeCollector {
        sink: IssueSink {
            index: ctx.index,
            language: ctx.language,
            issues: Vec::new(),
        },
    };
    collector.visit_program(ctx.program);
    collector.sink.issues
}

struct IifeCollector<'a> {
    sink: IssueSink<'a>,
}
impl<'a> Visit<'a> for IifeCollector<'_> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if let Expression::ArrowFunctionExpression(arrow) = unparenthesized(&call.callee)
            && let Some(Expression::ParenthesizedExpression(body)) = arrow.body.as_expression()
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S7743",
                "IIFE with parenthesized arrow function body is considered unreadable.",
                body.span,
            );
        }
        walk_call_expression(self, call);
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7743_reports_parenthesized_iife_arrow_with_exact_message_and_span() {
        let source = "export const objectIife = (() => ({ value: 1 }))();";
        for report in [js(source), ts(source)] {
            let issues: Vec<_> = report
                .issues
                .iter()
                .filter(|i| i.rule_key.ends_with(":S7743"))
                .collect();
            assert_eq!(issues.len(), 1);
            assert_eq!(
                issues[0].message,
                "IIFE with parenthesized arrow function body is considered unreadable."
            );
            assert_eq!(
                issues[0].range,
                hoonarqube_ir::Range {
                    start: pos(1, 33),
                    end: pos(1, 47)
                }
            );
        }
    }

    #[test]
    fn s7743_covers_parenthesized_values_async_and_optional_invocations() {
        for (source, start, end) in [
            ("export const arrayIife = (() => ([1, 2]))();", 32, 40),
            ("export const numberIife = (() => (1 + 2))();", 33, 40),
            (
                "export const asyncIife = (async () => ({ value: 1 }))();",
                38,
                52,
            ),
            (
                "export const sequenceIife = (() => (console.log('x'), 3))();",
                35,
                56,
            ),
            (
                "export const optionalIife = (() => ({ value: 1 }))?.();",
                35,
                49,
            ),
        ] {
            let report = ts(source);
            let issues: Vec<_> = report
                .issues
                .iter()
                .filter(|i| i.rule_key.ends_with(":S7743"))
                .collect();
            assert_eq!(issues.len(), 1, "{source}");
            assert_eq!(
                issues[0].range,
                hoonarqube_ir::Range {
                    start: pos(1, start),
                    end: pos(1, end)
                }
            );
        }
    }

    #[test]
    fn s7743_preserves_noninvoked_block_and_nonparenthesized_controls() {
        let source = "const ordinary = () => ({ value: 1 });\nconst block = (() => { return { value: 1 }; })();\nconst direct = (() => 3)();\nconst named = (function () { return { value: 1 }; })();";
        assert_eq!(filtered(&ts(source), "S7743").len(), 0);
        assert_eq!(filtered(&js(source), "S7743").len(), 0);
    }
}
