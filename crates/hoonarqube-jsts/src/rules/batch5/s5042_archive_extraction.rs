use crate::rules::batch5::collectors::ARCHIVE_EXTRACT_APIS;
use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::rules::tier_c::walker::sink_callee_name;
use crate::support::RuleScope;
use oxc_ast::ast::CallExpression;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S5042`: archive extraction without extraction limits.
    pub(crate) fn check_archive_extraction(&mut self, call: &CallExpression<'_>) {
        let Some(name) = sink_callee_name(&call.callee) else {
            return;
        };
        if ARCHIVE_EXTRACT_APIS.contains(&name) {
            self.sink.emit_span(
                RuleScope::Both,
                "S5042",
                "Make sure extracting this archive safely limits file count and size.",
                call.span(),
            );
        }
    }
}
