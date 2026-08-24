use super::collectors::PromiseFlowCollector;
use crate::support::RuleScope;
use crate::support::identifier_name;
use crate::support::statement_as_expression;
use crate::support::static_property_name;
use crate::support::unparenthesized;
use oxc_ast::ast::Expression;
use oxc_ast::ast::TryStatement;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl PromiseFlowCollector<'_> {
    /// `S4822` logic extracted from `visit_try_statement`.
    pub(crate) fn check_s4822_try_statement(&mut self, it: &TryStatement<'_>) {
        // `S4822`: await-less promise-producing calls escape the catch.
        for statement in &it.block.body {
            let Some(expression) = statement_as_expression(statement) else {
                continue;
            };
            if matches!(expression, Expression::AwaitExpression(_)) {
                continue;
            }
            if let Expression::CallExpression(call) = unparenthesized(expression) {
                let promise_api = identifier_name(&call.callee) == Some("fetch")
                    || call
                        .callee
                        .as_member_expression()
                        .is_some_and(|member| static_property_name(member) == Some("then"));
                if promise_api {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S4822",
                        "Await this promise; otherwise its failure bypasses the \"catch\".",
                        statement.span(),
                    );
                }
            }
        }
    }
}
