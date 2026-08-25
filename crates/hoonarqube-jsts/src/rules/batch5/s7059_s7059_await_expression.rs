use super::collectors::TsTypeCollector;
use crate::support::RuleScope;
use crate::support::unparenthesized;
use oxc_ast::ast::AwaitExpression;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Expression;
use oxc_span::GetSpan;

/// `S7059` helper: is the callee an async function/arrow expression?
fn callee_is_async_function(callee: &Expression<'_>) -> bool {
    match unparenthesized(callee) {
        Expression::ArrowFunctionExpression(arrow) => arrow.r#async,
        Expression::FunctionExpression(function) => function.r#async,
        _ => false,
    }
}

// Generated per-rule checks (moved out of traversal overrides).
impl TsTypeCollector<'_, '_> {
    /// `S7059` logic extracted from `visit_call_expression`.
    pub(crate) fn check_s7059_call_expression(&mut self, it: &CallExpression<'_>) {
        if self.constructor_depth > 0 && callee_is_async_function(&it.callee) {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S7059",
                "Move this asynchronous work out of the constructor.",
                it.span(),
            );
        }
    }

    /// `S7059` logic extracted from `visit_await_expression`.
    pub(crate) fn check_s7059_await_expression(&mut self, it: &AwaitExpression<'_>) {
        if self.constructor_depth > 0 {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S7059",
                "Move this asynchronous work out of the constructor.",
                it.span(),
            );
        }
    }
}
