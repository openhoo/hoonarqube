// Residual rule machinery for 'batch2d' (extracted from lib.rs).
use super::collectors::RootedMemberScanner;
use crate::rules::batch2d::s3512_es_idioms::EsIdiomCollector;
use crate::rules::shared::is_equality_operator;
use crate::support::RuleScope;
use crate::support::identifier_name;
use crate::support::unparenthesized;
use oxc_ast::ast::Expression;
use oxc_ast::ast::LogicalExpression;
use oxc_ast::ast::LogicalOperator;
use oxc_ast_visit::Visit;
use oxc_span::GetSpan;

/// Identifier compared against `null`/`undefined` by one side of an `&&`
/// guard (`S6582`).
fn null_guard_target<'a>(expression: &'a Expression<'a>) -> Option<&'a str> {
    let Expression::BinaryExpression(binary) = unparenthesized(expression) else {
        return None;
    };
    if !is_equality_operator(binary.operator) {
        return None;
    }
    let is_nullish = |expression: &Expression<'_>| {
        matches!(expression, Expression::NullLiteral(_))
            || identifier_name(expression) == Some("undefined")
    };
    match (&binary.left, &binary.right) {
        (Expression::Identifier(identifier), other)
        | (other, Expression::Identifier(identifier))
            if is_nullish(other) =>
        {
            Some(&identifier.name)
        }
        _ => None,
    }
}

// Generated per-rule checks (moved out of traversal overrides).
impl EsIdiomCollector<'_> {
    /// `S6582` logic extracted from `visit_logical_expression`.
    pub(crate) fn check_s6582_logical_expression(&mut self, it: &LogicalExpression<'_>) {
        // `S6582`: `x !== null && x.member` rewrites to optional chaining.
        if it.operator == LogicalOperator::And
            && let Some(root) = null_guard_target(&it.left)
        {
            let mut scanner = RootedMemberScanner { root, found: false };
            scanner.visit_expression(&it.right);
            if scanner.found {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6582",
                    "Use optional chaining (\"?.\") instead of this null check.",
                    it.span(),
                );
            }
        }
    }
}
