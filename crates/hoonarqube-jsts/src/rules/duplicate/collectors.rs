// Residual rule machinery for 'duplicate' (extracted from lib.rs).
use oxc_ast::ast::Expression;

pub(crate) fn is_literal_expression(expression: &Expression<'_>) -> bool {
    matches!(
        expression,
        Expression::BigIntLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_)
            | Expression::NumericLiteral(_)
            | Expression::RegExpLiteral(_)
            | Expression::StringLiteral(_)
    )
}
