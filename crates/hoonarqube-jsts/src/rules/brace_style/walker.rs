// Family walker for 'brace_style' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::support::{
    IssueSink, LineIndex, RuleScope, next_non_trivia_offset, previous_non_trivia_offset, to_u32,
};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    BlockStatement, ClassBody, DoWhileStatement, ForInStatement, ForOfStatement, ForStatement,
    FunctionBody, IfStatement, Statement, SwitchStatement, TryStatement, WhileStatement,
    WithStatement,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_block_statement, walk_class_body, walk_do_while_statement, walk_for_in_statement,
    walk_for_of_statement, walk_for_statement, walk_function_body, walk_if_statement,
    walk_switch_statement, walk_try_statement, walk_while_statement, walk_with_statement,
};
use oxc_span::{GetSpan, Span};
use std::collections::HashSet;

fn check_brace_style(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = BraceStyleCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        source,
        controlled_blocks: HashSet::new(),
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// `S1105` (1tbs opening-brace placement) over block bodies, function
/// bodies, class bodies, and switch headers.
struct BraceStyleCollector<'a, 'index> {
    sink: IssueSink<'index>,
    source: &'a str,
    /// Span starts of `BlockStatement`s that are the body of a controlling
    /// statement (`if`/`for`/`while`/`do`/`try`/`catch`/`with`). Bare
    /// scoping blocks have no controlling statement and are never checked,
    /// matching the reference rule.
    controlled_blocks: HashSet<u32>,
}

impl BraceStyleCollector<'_, '_> {
    /// Flags `brace_offset` (the `{`) when the nearest preceding token ends
    /// on an earlier line.
    fn check_opening_brace(&mut self, brace_offset: u32) {
        let Some(previous) = previous_non_trivia_offset(self.source, brace_offset) else {
            return;
        };
        let brace_line = self.sink.index.pos(brace_offset).line;
        let previous_line = self.sink.index.pos(previous).line;
        if previous_line != brace_line {
            self.sink.emit_span(
                RuleScope::Both,
                "S1105",
                "Opening curly brace does not appear on the same line as controlling statement.",
                Span::new(brace_offset, brace_offset.saturating_add(1)),
            );
        }
    }

    /// The switch header's `{`: the first non-trivia byte after the
    /// discriminant, skipping the header's closing parenthesis group(s)
    /// (`switch (x)`, `switch ((x))`) — nothing else may sit between them.
    fn switch_opening_brace_offset(&self, it: &SwitchStatement<'_>) -> Option<u32> {
        let bytes = self.source.as_bytes();
        let mut i = usize::try_from(it.discriminant.span().end)
            .ok()?
            .min(bytes.len());
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n' | b')') {
            i += 1;
        }
        let offset = next_non_trivia_offset(self.source, i)?;
        (bytes.get(offset) == Some(&b'{')).then_some(to_u32(offset))
    }

    /// Records `statement` when it is a block body so the shared
    /// `visit_block_statement` hook can check its opening brace.
    fn mark_controlled_block(&mut self, statement: &Statement<'_>) {
        if let Statement::BlockStatement(block) = statement {
            self.controlled_blocks.insert(block.span.start);
        }
    }
}
impl<'a> Visit<'a> for BraceStyleCollector<'a, '_> {
    fn visit_block_statement(&mut self, it: &BlockStatement<'a>) {
        if self.controlled_blocks.contains(&it.span.start) {
            self.check_opening_brace(it.span.start);
        }
        walk_block_statement(self, it);
    }

    fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
        self.mark_controlled_block(&it.consequent);
        if let Some(alternate) = &it.alternate {
            self.mark_controlled_block(alternate);
        }
        walk_if_statement(self, it);
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'a>) {
        self.mark_controlled_block(&it.body);
        walk_for_statement(self, it);
    }

    fn visit_for_in_statement(&mut self, it: &ForInStatement<'a>) {
        self.mark_controlled_block(&it.body);
        walk_for_in_statement(self, it);
    }

    fn visit_for_of_statement(&mut self, it: &ForOfStatement<'a>) {
        self.mark_controlled_block(&it.body);
        walk_for_of_statement(self, it);
    }

    fn visit_while_statement(&mut self, it: &WhileStatement<'a>) {
        self.mark_controlled_block(&it.body);
        walk_while_statement(self, it);
    }

    fn visit_do_while_statement(&mut self, it: &DoWhileStatement<'a>) {
        self.mark_controlled_block(&it.body);
        walk_do_while_statement(self, it);
    }

    fn visit_with_statement(&mut self, it: &WithStatement<'a>) {
        self.mark_controlled_block(&it.body);
        walk_with_statement(self, it);
    }

    fn visit_try_statement(&mut self, it: &TryStatement<'a>) {
        self.controlled_blocks.insert(it.block.span.start);
        if let Some(handler) = &it.handler {
            self.controlled_blocks.insert(handler.body.span.start);
        }
        if let Some(finalizer) = &it.finalizer {
            self.controlled_blocks.insert(finalizer.span.start);
        }
        walk_try_statement(self, it);
    }

    fn visit_function_body(&mut self, it: &FunctionBody<'a>) {
        self.check_opening_brace(it.span.start);
        walk_function_body(self, it);
    }

    fn visit_class_body(&mut self, it: &ClassBody<'a>) {
        self.check_opening_brace(it.span.start);
        walk_class_body(self, it);
    }

    fn visit_switch_statement(&mut self, it: &SwitchStatement<'a>) {
        if let Some(offset) = self.switch_opening_brace_offset(it) {
            self.check_opening_brace(offset);
        }
        walk_switch_statement(self, it);
    }
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_brace_style(ctx.program, ctx.source, ctx.index, ctx.language)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn brace_style_tolerates_comments_between_head_and_brace() {
        // The trailing comment shares the head's line; the brace on the next
        // line is still flagged against it.
        let trailing = js("if (a) // note\n{\n  b();\n}\n");
        let braces: Vec<_> = trailing
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S1105"))
            .map(|issue| (issue.range.start.line, issue.range.start.column))
            .collect();
        assert_eq!(braces, vec![(2, 0)]);

        // A comment-only line between head and brace is skipped entirely.
        let separated = js("if (a)\n// note\n{\n  b();\n}\n");
        let braces: Vec<_> = separated
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S1105"))
            .map(|issue| (issue.range.start.line, issue.range.start.column))
            .collect();
        assert_eq!(braces, vec![(3, 0)]);

        // Fully 1tbs code stays clean across constructs.
        assert_eq!(
            count_key(
                &js_keys(
                    "function good() {\n  if (a) {\n    b();\n  } else {\n    c();\n  }\n  try {\n    d();\n  } catch (e) {\n    f();\n  } finally {\n    g();\n  }\n  while (a) {\n    h();\n  }\n}\n"
                ),
                "javascript:S1105"
            ),
            0
        );
    }

    #[test]
    fn s1105_flags_braces_on_their_own_line_across_constructs() {
        let flagged = |source: &str| -> Vec<(u32, u32)> {
            let report = js(source);
            report
                .issues
                .iter()
                .filter(|issue| issue.rule_key.ends_with(":S1105"))
                .map(|issue| (issue.range.start.line, issue.range.start.column))
                .collect()
        };
        // Function body brace.
        assert_eq!(flagged("function f()\n{\n  return 1;\n}\n"), vec![(2, 0)]);
        // Class body brace.
        assert_eq!(flagged("class A\n{\n  m() {}\n}\n"), vec![(2, 0)]);
        // `else` branch block brace.
        assert_eq!(
            flagged("if (a) {\n  b();\n} else\n{\n  c();\n}\n"),
            vec![(4, 0)]
        );
    }

    #[test]
    fn s1105_switch_header_brace_skips_parenthesis_groups() {
        // The `{` on the next line is located past both closing parens.
        assert_eq!(
            count_key(
                &js_keys("switch ((x))\n{\n  case 1:\n    break;\n}\n"),
                "javascript:S1105"
            ),
            1
        );
        // Same-line header brace over nested parens stays clean.
        assert_eq!(
            count_key(
                &js_keys("switch ((x)) { case 1: break; }\n"),
                "javascript:S1105"
            ),
            0
        );
    }

    #[test]
    fn s1105_bare_scoping_blocks_have_no_controlling_statement() {
        // Regression of #517: a standalone block used for lexical scoping
        // has no controlling statement for the brace to share a line with,
        // so the reference rule never flags it.
        let bare = "function scan() {\n    let pos = 0;\n    {\n        const escapedValue = pos + 1;\n        pos = escapedValue;\n    }\n    return pos;\n}\n";
        assert_eq!(count_key(&js_keys(bare), "javascript:S1105"), 0);

        // Control-statement bodies still flag on a misplaced brace.
        let flagged = js_keys("if (a)\n{\n  b();\n}\nwhile (a)\n{\n  c();\n}\n");
        assert_eq!(count_key(&flagged, "javascript:S1105"), 2);
    }
}
