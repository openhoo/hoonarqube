use crate::rules::batch5::collectors::PATH_LOOKUP_APIS;
use crate::rules::batch5::collectors::SHELL_EXEC_NAMES;
use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::rules::batch5::collectors::first_string_argument;
use crate::rules::tier_c::walker::sink_callee_name;
use crate::support::RuleScope;
use oxc_ast::ast::CallExpression;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S4721` and `S4036`: shell-interpreter sinks and PATH lookups.
    pub(crate) fn check_shell_exec(&mut self, call: &CallExpression<'_>) {
        let Some(name) = sink_callee_name(&call.callee) else {
            return;
        };
        if SHELL_EXEC_NAMES.contains(&name) {
            self.sink.emit_span(
                RuleScope::Both,
                "S4721",
                "Prefer 'spawn' over 'exec': 'exec' runs a shell interpreter.",
                call.span(),
            );
        }
        if PATH_LOOKUP_APIS.contains(&name)
            && let Some(executable) = first_string_argument(call)
            && !executable.contains('/')
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S4036",
                "Specify the full path to this executable.",
                call.span(),
            );
        }
    }
}
