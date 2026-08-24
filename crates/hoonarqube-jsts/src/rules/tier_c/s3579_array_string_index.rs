use super::walker::{TierCLiteralCollector, sink_callee_name};
use crate::support::RuleScope;
use crate::support::member_object;
use crate::support::unparenthesized;
use oxc_ast::ast::Expression;
use oxc_ast::ast::MemberExpression;
use oxc_span::GetSpan;

impl TierCLiteralCollector<'_> {
    /// `S3579`: string-literal indexes into array-shaped receivers.
    pub(crate) fn check_array_string_index(&mut self, member: &MemberExpression<'_>) {
        let MemberExpression::ComputedMemberExpression(computed) = member else {
            return;
        };
        let Expression::StringLiteral(_) = unparenthesized(&computed.expression) else {
            return;
        };
        let array_shaped = match unparenthesized(member_object(member)) {
            Expression::ArrayExpression(_) => true,
            Expression::CallExpression(call) => {
                ARRAY_RETURNING_APIS.contains(&sink_callee_name(&call.callee).unwrap_or_default())
            }
            _ => false,
        };
        if array_shaped {
            self.sink.emit_span(
                RuleScope::Both,
                "S3579",
                "Use a numeric index to access this array element.",
                member.span(),
            );
        }
    }
}

/// Member names whose call results are arrays (`S3579` receivers).
pub(crate) const ARRAY_RETURNING_APIS: [&str; 11] = [
    "split", "slice", "concat", "join", "reverse", "sort", "filter", "map", "splice", "flat",
    "flatMap",
];
