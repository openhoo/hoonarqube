// Family walker for 'brace_style' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::support::{
    IssueSink, LineIndex, RuleScope, next_non_trivia_offset, previous_non_trivia_offset, to_u32,
};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{BlockStatement, ClassBody, FunctionBody, SwitchStatement};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_block_statement, walk_class_body, walk_function_body, walk_switch_statement,
};
use oxc_span::{GetSpan, Span};

pub(crate) fn check_brace_style(
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
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// `S1105` (1tbs opening-brace placement) over block bodies, function
/// bodies, class bodies, and switch headers.
pub(crate) struct BraceStyleCollector<'a, 'index> {
    pub(crate) sink: IssueSink<'index>,
    pub(crate) source: &'a str,
}

impl BraceStyleCollector<'_, '_> {
    /// Flags `brace_offset` (the `{`) when the nearest preceding token ends
    /// on an earlier line.
    pub(crate) fn check_opening_brace(&mut self, brace_offset: u32) {
        let Some(previous) = previous_non_trivia_offset(self.source, brace_offset) else {
            return;
        };
        let brace_line = self.sink.index.pos(brace_offset).line;
        let previous_line = self.sink.index.pos(previous).line;
        if previous_line != brace_line {
            self.sink.emit_span(
                RuleScope::Both,
                "S1105",
                "Move the opening curly brace to the end of the previous line.",
                Span::new(brace_offset, brace_offset.saturating_add(1)),
            );
        }
    }

    /// The switch header's `{`: the first non-trivia byte after the
    /// discriminant, skipping the header's closing parenthesis group(s)
    /// (`switch (x)`, `switch ((x))`) — nothing else may sit between them.
    pub(crate) fn switch_opening_brace_offset(&self, it: &SwitchStatement<'_>) -> Option<u32> {
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
}

impl<'a> Visit<'a> for BraceStyleCollector<'a, '_> {
    fn visit_block_statement(&mut self, it: &BlockStatement<'a>) {
        self.check_opening_brace(it.span.start);
        walk_block_statement(self, it);
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
