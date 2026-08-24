use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::support::RuleScope;
use oxc_ast::ast::Expression;
use oxc_ast::ast::MemberExpression;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S5759`: trusting the `X-Forwarded-For` header.
    pub(crate) fn check_forwarded_header_trust(&mut self, member: &MemberExpression<'_>) {
        let MemberExpression::ComputedMemberExpression(computed) = member else {
            return;
        };
        let Expression::StringLiteral(literal) = &computed.expression else {
            return;
        };
        if literal.value.to_ascii_lowercase() == "x-forwarded-for" {
            self.sink.emit_span(
                RuleScope::Both,
                "S5759",
                "Make sure this forwarded header comes from a trusted source.",
                member.span(),
            );
        }
    }
}
