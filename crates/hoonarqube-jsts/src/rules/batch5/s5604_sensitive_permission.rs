use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::support::RuleScope;
use crate::support::member_root_name;
use crate::support::static_property_name;
use oxc_ast::ast::MemberExpression;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S5604`: sensitive permission surfaces worth reviewing.
    pub(crate) fn check_sensitive_permission(&mut self, member: &MemberExpression<'_>) {
        let Some(property) = static_property_name(member) else {
            return;
        };
        let flagged = (property == "geolocation" && member_root_name(member) == Some("navigator"))
            || (property == "requestPermission"
                && member_root_name(member) == Some("Notification"));
        if flagged {
            self.sink.emit_span(
                RuleScope::Both,
                "S5604",
                "Make sure requesting this sensitive permission is safe here.",
                member.span(),
            );
        }
    }
}
