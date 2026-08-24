use super::collectors::KeywordPlacementCollector;
use crate::support::RuleScope;
use crate::support::to_u32;
use oxc_span::Span;

impl KeywordPlacementCollector<'_, '_> {
    /// `S3972`: the keyword joining two blocks (`else`, `catch`, `finally`)
    /// must start on its own line after the preceding closing brace; a
    /// keyword sharing the brace's line is flagged.
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
