use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::support::RuleScope;
use crate::support::member_root_name;
use crate::support::static_property_name;
use oxc_ast::ast::MemberExpression;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S4829`: standard-input reads worth reviewing.
    pub(crate) fn check_standard_input_reads(&mut self, it: &MemberExpression<'_>) {
        if member_root_name(it) == Some("process") && static_property_name(it) == Some("stdin") {
            self.sink.emit_span(
                RuleScope::Both,
                "S4829",
                "Make sure that reading the standard input is safe here.",
                it.span(),
            );
        }
    }
}
