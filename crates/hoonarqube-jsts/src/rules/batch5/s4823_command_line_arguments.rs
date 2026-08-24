use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::support::RuleScope;
use crate::support::member_root_name;
use crate::support::static_property_name;
use oxc_ast::ast::MemberExpression;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S4823`: command-line argument accesses worth reviewing.
    pub(crate) fn check_command_line_arguments(&mut self, it: &MemberExpression<'_>) {
        if member_root_name(it) == Some("process")
            && matches!(static_property_name(it), Some("argv" | "execArgv"))
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S4823",
                "Make sure using command line arguments is safe here.",
                it.span(),
            );
        }
    }
}
