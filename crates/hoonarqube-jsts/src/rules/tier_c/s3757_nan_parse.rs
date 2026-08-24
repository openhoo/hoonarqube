use super::walker::TierCLiteralCollector;
use crate::rules::expression::s1528_constructor_calls::argument_expression;
use crate::support::RuleScope;
use crate::support::callee_name;
use crate::support::unparenthesized;
use oxc_ast::ast::BinaryExpression;
use oxc_ast::ast::BinaryOperator;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Expression;
use oxc_span::GetSpan;

impl TierCLiteralCollector<'_> {
    /// `S3757`: literal folds that always produce 'NaN'.
    pub(crate) fn check_nan_fold(&mut self, expression: &BinaryExpression<'_>) {
        let is_zero = |operand: &Expression| {
            matches!(
                unparenthesized(operand),
                Expression::NumericLiteral(literal) if literal.value == 0.0
            )
        };
        let is_infinity = |operand: &Expression| {
            matches!(
                unparenthesized(operand),
                Expression::Identifier(identifier) if identifier.name == "Infinity"
            )
        };
        let nan = match expression.operator {
            BinaryOperator::Division => is_zero(&expression.left) && is_zero(&expression.right),
            BinaryOperator::Multiplication => {
                (is_zero(&expression.left) && is_infinity(&expression.right))
                    || (is_infinity(&expression.left) && is_zero(&expression.right))
            }
            _ => false,
        };
        if nan {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S3757",
                "This operation always produces 'NaN'.",
                expression.span(),
            );
        }
    }

    /// `S3757`: parse calls over non-numeric text and `Number(undefined)`.
    pub(crate) fn check_nan_parse(&mut self, call: &CallExpression<'_>) {
        let Some(name) = callee_name(call) else {
            return;
        };
        if !matches!(name, "parseInt" | "parseFloat" | "Number") {
            return;
        }
        let Some(argument) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        let flagged = match name {
            "parseInt" | "parseFloat" => {
                let Expression::StringLiteral(literal) = unparenthesized(argument) else {
                    return;
                };
                let text = literal.value.trim_start();
                let text = text.strip_prefix(['+', '-']).unwrap_or(text);
                !text.starts_with(|character: char| character.is_ascii_digit() || character == '.')
            }
            _ => {
                matches!(
                    unparenthesized(argument),
                    Expression::Identifier(identifier) if identifier.name == "undefined"
                ) || matches!(
                    unparenthesized(argument),
                    Expression::ObjectExpression(_) | Expression::ArrayExpression(_)
                )
            }
        };
        if flagged {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S3757",
                "This expression evaluates to 'NaN'.",
                call.span(),
            );
        }
    }
}
