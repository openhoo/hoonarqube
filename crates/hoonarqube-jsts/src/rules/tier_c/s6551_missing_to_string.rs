// Rule module s6551_missing_to_string (generated).
use super::walker::TierCCoercionCollector;
use crate::support::{RuleScope, unparenthesized};
use oxc_ast::ast::{BinaryExpression, BinaryOperator, Expression, TemplateLiteral};
use oxc_span::Span;

impl<'a> TierCCoercionCollector<'_, '_> {
    /// `S6551` over template interpolations of file-local instances whose
    /// class declares no `toString` member.
    pub(crate) fn check_template_coercion(&mut self, it: &TemplateLiteral<'a>) {
        for expression in &it.expressions {
            if let Some(span) = self.tracked_instance(expression) {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6551",
                    "Provide a 'toString()' method for this class or convert it explicitly.",
                    span,
                );
            }
        }
    }

    /// `S6551` over string concatenations that coerce a file-local instance.
    pub(crate) fn check_concat_coercion(&mut self, it: &BinaryExpression<'a>) {
        if it.operator == BinaryOperator::Addition {
            let instance_span = if is_string_operand(&it.left) {
                self.tracked_instance(&it.right)
            } else if is_string_operand(&it.right) {
                self.tracked_instance(&it.left)
            } else {
                None
            };
            if let Some(span) = instance_span {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6551",
                    "Provide a 'toString()' method for this class or convert it explicitly.",
                    span,
                );
            }
        }
    }

    /// Span of an identifier bound to a file-local class lacking `toString`.
    fn tracked_instance(&self, expression: &Expression<'_>) -> Option<Span> {
        match unparenthesized(expression) {
            Expression::Identifier(identifier)
                if self.census.instances.contains_key(identifier.name.as_str()) =>
            {
                Some(identifier.span)
            }
            _ => None,
        }
    }
}

/// Whether the operand is textual, so `+` coerces its other side to string.
fn is_string_operand(expression: &Expression<'_>) -> bool {
    matches!(
        unparenthesized(expression),
        Expression::StringLiteral(_) | Expression::TemplateLiteral(_)
    )
}
