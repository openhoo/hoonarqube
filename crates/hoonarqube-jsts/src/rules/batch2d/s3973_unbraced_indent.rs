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
            self.sink.emit_span(
                RuleScope::Both,
                "S3973",
                "Indent this statement deeper than its parent statement.",
                body.span(),
            );
        }
    }
}
