// Family walker for 'call_argument_lines'.
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::rules::shared::argument_expression;
use crate::support::{
    IssueSink, LineIndex, RuleScope, next_non_trivia_offset, previous_non_trivia_offset,
    unparenthesized,
};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{CallExpression, Expression, TaggedTemplateExpression};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{walk_call_expression, walk_tagged_template_expression};
use oxc_span::{GetSpan, Span};

fn check_call_argument_lines(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = CallArgumentCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        source,
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// `S1472`: single-argument calls whose argument list starts on a line of its
/// own, and tagged templates whose quasi starts on a line of its own. The
/// hazard is accidental continuation: a newline in front of `(` or of a
/// template literal joins the previous expression instead of starting a new
/// statement. Arguments that merely continue onto further lines, calls with
/// several arguments, and curried callee chains (`foo(bar)(baz)`) are outside
/// the rule.
struct CallArgumentCollector<'a, 'index> {
    sink: IssueSink<'index>,
    source: &'a str,
}

impl<'a> Visit<'a> for CallArgumentCollector<'a, '_> {
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        // Only the outermost call of a chain is checked; a callee that is
        // itself a call is excluded, like the reference rule.
        if !matches!(unparenthesized(&it.callee), Expression::CallExpression(_))
            && it.arguments.len() == 1
            && let Some(first) = it.arguments.first().and_then(argument_expression)
        {
            self.check_argument_list(it, first.span().start);
        }
        walk_call_expression(self, it);
    }

    fn visit_tagged_template_expression(&mut self, it: &TaggedTemplateExpression<'a>) {
        let tag_line = self.sink.index.pos(it.tag.span().end).line;
        let quasi_start = it.quasi.span().start;
        if tag_line != self.sink.index.pos(quasi_start).line {
            self.sink.emit_span(
                RuleScope::Both,
                "S1472",
                &format!("Make this template literal start on line {tag_line}."),
                Span::sized(quasi_start, 1),
            );
        }
        walk_tagged_template_expression(self, it);
    }
}

impl CallArgumentCollector<'_, '_> {
    /// A call is flagged when the `(` opening its argument list starts on a
    /// line of its own. Scans the source between the callee (or its type
    /// arguments) and the first argument, so a closing paren belonging to a
    /// parenthesized callee anchors the check exactly like the reference
    /// token walk.
    fn check_argument_list(&mut self, call: &CallExpression<'_>, first_argument_start: u32) {
        let mut anchor = call
            .type_arguments
            .as_deref()
            .map_or(call.callee.span().end, |types| types.span.end);
        let Some(initial) = next_non_trivia_offset(self.source, anchor as usize) else {
            return;
        };
        let Some(first) = u32::try_from(initial)
            .ok()
            .filter(|offset| *offset < first_argument_start)
        else {
            return;
        };
        let mut offset = first;
        while offset < first_argument_start && self.source[offset as usize..].starts_with(')') {
            anchor = offset + 1;
            let Some(candidate) = next_non_trivia_offset(self.source, anchor as usize) else {
                return;
            };
            match u32::try_from(candidate)
                .ok()
                .filter(|next| *next < first_argument_start)
            {
                Some(next) => offset = next,
                None => return,
            }
        }
        if offset >= first_argument_start {
            return;
        }
        let anchor_line = match previous_non_trivia_offset(self.source, offset) {
            Some(previous) => self.sink.index.pos(previous).line,
            None => self.sink.index.pos(anchor).line,
        };
        let open_line = self.sink.index.pos(offset).line;
        if anchor_line == open_line {
            return;
        }
        // Single-line argument lists are reported as a whole; lists spanning
        // lines are reported only at their start.
        let span = if self.sink.index.pos(call.span.end).line == open_line {
            Span::new(offset, call.span.end)
        } else {
            Span::sized(offset, 1)
        };
        self.sink.emit_span(
            RuleScope::Both,
            "S1472",
            &format!("Make those call arguments start on line {anchor_line}."),
            span,
        );
    }
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_call_argument_lines(ctx.program, ctx.source, ctx.index, ctx.language)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn detached_argument_lists_are_flagged() {
        let split = js("foo\n  (bar);\n");
        let s1472: Vec<_> = split
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S1472"))
            .collect();
        assert_eq!(s1472.len(), 1);
        assert_eq!(s1472[0].range.start.line, 2);

        // `(` staying on the callee's line is never a hazard, no matter where
        // the arguments themselves continue.
        assert_eq!(
            count_key(&js_keys("foo(\n  bar);\n"), "javascript:S1472"),
            0
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
    fn multi_argument_and_curried_calls_stay_clean() {
        // Several arguments never produce the single-argument hazard shape.
        assert_eq!(
            count_key(&js_keys("foo\n  (bar, baz, qux);\n"), "javascript:S1472"),
            0
        );
        // Curried chains are evaluated per call; each `(` keeps its line.
        assert_eq!(
            count_key(
                &js_keys("foo(bar)\n  (baz)\n  (qux);\n"),
                "javascript:S1472"
            ),
            0
        );
        // A parenthesized callee anchors at its own closing paren.
        assert_eq!(
            count_key(&js_keys("(foo\n)((bar));\n"), "javascript:S1472"),
            0
        );
    }

    #[test]
    fn accidental_continuation_after_statement_is_flagged() {
        // The classic ASI hazard: `(x || y)` continues `b`.
        let continuation = js("var a = b\n(x || y).doSomething();\n");
        assert_eq!(
            count_key(&report_keys(&continuation), "javascript:S1472"),
            1
        );
        // Type arguments anchor the check when present.
        let typed = ts("foo<string>\n  ('bar');\n");
        assert_eq!(count_key(&report_keys(&typed), "typescript:S1472"), 1);
    }

    #[test]
    fn detached_template_quasi_is_flagged() {
        let tagged = js("let x = function() {}\n`hello`;\n");
        assert_eq!(count_key(&report_keys(&tagged), "javascript:S1472"), 1);
        assert_eq!(count_key(&js_keys("tag`hello`;\n"), "javascript:S1472"), 0);
    }
}
