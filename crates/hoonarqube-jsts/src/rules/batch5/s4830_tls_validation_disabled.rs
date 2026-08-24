use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::support::RuleScope;
use crate::support::expression_root_name;
use oxc_ast::ast::AssignmentExpression;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S4830`: globally disabled TLS certificate validation.
    pub(crate) fn check_tls_validation_disabled(&mut self, assignment: &AssignmentExpression<'_>) {
        let Some(oxc_ast::ast::SimpleAssignmentTarget::StaticMemberExpression(member)) =
            assignment.left.as_simple_assignment_target()
        else {
            return;
        };
        if member.property.name == "NODE_TLS_REJECT_UNAUTHORIZED"
            && expression_root_name(&member.object) == Some("process")
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S4830",
                "Do not disable TLS certificate validation globally.",
                assignment.span(),
            );
        }
    }
}
