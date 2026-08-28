use super::collectors::DuplicationCollector;
use crate::support::RuleScope;
use oxc_span::Span;

impl DuplicationCollector<'_> {
    pub(crate) fn emit_duplicate_key(&mut self, name: &str, span: Span) {
        self.sink.emit_span(
            RuleScope::Both,
            "S1534",
            &format!("Duplicate key '{}'.", name.trim_matches(['\'', '"'])),
            span,
        );
    }
}
