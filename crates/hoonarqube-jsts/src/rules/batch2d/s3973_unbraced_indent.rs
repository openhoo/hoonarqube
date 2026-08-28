use super::collectors::KeywordPlacementCollector;
use crate::support::RuleScope;
use oxc_ast::ast::Statement;
use oxc_span::{GetSpan, Span};

impl KeywordPlacementCollector<'_, '_> {
    /// `S3973`: an unbraced body starting on a later line must be indented
    /// strictly deeper than its head statement.
    pub(crate) fn check_unbraced_indent(&mut self, head: Span, body: &Statement<'_>) {
        if matches!(
            body,
            Statement::BlockStatement(_) | Statement::EmptyStatement(_)
        ) {
            return;
        }
        let head_start = self.index.pos(head.start);
        let body_start = self.index.pos(body.span().start);
        if body_start.line > head_start.line && body_start.column <= head_start.column {
            let text = crate::support::source_slice(self.source, head);
            let keyword = ["while", "switch", "for", "if", "do"]
                .into_iter()
                .find(|keyword| text.starts_with(keyword))
                .unwrap_or("statement");
            self.sink.emit_span(
                RuleScope::Both,
                "S3973",
                &format!(
                    "Use curly braces or indentation to denote the code conditionally executed by this \"{keyword}\"."
                ),
                Span::new(
                    head.start,
                    head.start + u32::try_from(keyword.len()).unwrap_or_default(),
                ),
            );
        }
    }
}
