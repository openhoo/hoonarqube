use super::collectors::KeywordPlacementCollector;
use crate::support::RuleScope;
use crate::support::to_u32;
use oxc_ast::ast::Statement;
use oxc_span::{GetSpan, Span};

impl KeywordPlacementCollector<'_, '_> {
    /// `S3972`: adjacent sibling `if` statements must not share a line at
    /// the closing brace/opening keyword boundary.
    pub(crate) fn check_sibling_ifs(&mut self, statements: &[Statement<'_>]) {
        for pair in statements.windows(2) {
            let (Statement::IfStatement(preceding), Statement::IfStatement(following)) =
                (&pair[0], &pair[1])
            else {
                continue;
            };
            let preceding_span = preceding.span();
            let following_span = following.span();
            let preceding_start_line = self.index.pos(preceding_span.start).line;
            let preceding_end_line = self.index.pos(preceding_span.end).line;
            let following_start_line = self.index.pos(following_span.start).line;
            let following_end_line = self.index.pos(following_span.end).line;
            if preceding_end_line != following_start_line
                || preceding_start_line == following_end_line
            {
                continue;
            }
            let start = following_span.start;
            self.sink.emit_span(
                RuleScope::Both,
                "S3972",
                "Move this \"if\" to a new line or add the missing \"else\".",
                Span::new(start, start + to_u32(2)),
            );
        }
    }
    /// Native S3972 also reports `else`, `catch`, and `finally` that share
    /// a closing brace line; these findings intentionally have no quickfix.
    pub(crate) fn check_keyword_line(&mut self, previous: Span, following: Span, keyword: &str) {
        let gap = &self.source[previous.end as usize..following.start as usize];
        if !gap.contains('\n') {
            let anchor = gap
                .find(keyword)
                .map_or(following.start, |at| previous.end + to_u32(at));
            self.sink.emit_span(
                RuleScope::Both,
                "S3972",
                "Move this keyword onto its own line after the closing brace.",
                Span::new(anchor, anchor + to_u32(keyword.len())),
            );
        }
    }
}
