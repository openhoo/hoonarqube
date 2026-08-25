use super::walker::TierCAwaitCollector;
use crate::support::RuleScope;
use crate::support::expression_root_name;
use crate::support::unparenthesized;
use oxc_ast::ast::Expression;
use oxc_span::GetSpan;

impl TierCAwaitCollector<'_, '_> {
    /// `S4123`: awaited values that are provably not promises.
    pub(crate) fn check_awaited_value(&mut self, argument: &Expression<'_>) {
        let flagged = match unparenthesized(argument) {
            Expression::StringLiteral(_)
            | Expression::TemplateLiteral(_)
            | Expression::NumericLiteral(_)
            | Expression::BigIntLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_)
            | Expression::ArrayExpression(_)
            | Expression::ObjectExpression(_) => true,
            Expression::Identifier(identifier) => identifier.name == "undefined",
            Expression::CallExpression(call) => match &call.callee {
                Expression::Identifier(callee) => {
                    if self.is_known_sync_local(&callee.name) {
                        true
                    } else {
                        SYNC_GLOBAL_APIS.contains(&callee.name.as_str())
                    }
                }
                Expression::StaticMemberExpression(member) => SYNC_MEMBER_ROOTS
                    .contains(&expression_root_name(&member.object).unwrap_or_default()),
                _ => false,
            },
            _ => false,
        };
        if flagged {
            self.sink.emit_span(
                RuleScope::Both,
                "S4123",
                "This value is not a promise; 'await' has no effect here.",
                argument.span(),
            );
        }
    }

    fn is_known_sync_local(&self, name: &str) -> bool {
        self.census
            .functions
            .get(name)
            .is_some_and(|facts| !facts.r#async)
    }
}

/// Member roots whose calls are synchronous (`S4123`).
const SYNC_MEMBER_ROOTS: [&str; 7] = [
    "Math", "Object", "JSON", "Reflect", "Array", "Date", "Number",
];

/// Plain globals whose calls are synchronous (`S4123`).
const SYNC_GLOBAL_APIS: [&str; 9] = [
    "parseInt",
    "parseFloat",
    "isNaN",
    "isFinite",
    "btoa",
    "atob",
    "String",
    "Number",
    "Boolean",
];
