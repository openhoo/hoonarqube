// Helpers shared across rule families (hoisted from rule-specific modules).
use crate::support::static_property_name;
use oxc_ast::ast::{
    BinaryOperator, CallExpression, Expression, MemberExpression, PropertyKey, RegExpLiteral,
    Statement,
};

/// `console` members flagged by `S106`.
pub(crate) const CONSOLE_METHODS: [&str; 8] = [
    "log", "info", "warn", "error", "debug", "trace", "dir", "table",
];

pub(crate) const SHELL_EXEC_FUNCTIONS: [&str; 5] =
    ["exec", "execSync", "spawn", "spawnSync", "execFile"];

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

pub(crate) fn is_equality_operator(operator: BinaryOperator) -> bool {
    matches!(
        operator,
        BinaryOperator::Equality
            | BinaryOperator::Inequality
            | BinaryOperator::StrictEquality
            | BinaryOperator::StrictInequality
    )
}

pub(crate) fn is_unpinned_npm_install(command: &str) -> bool {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    if tokens.first() != Some(&"npm") || !matches!(tokens.get(1), Some(&"install" | &"i" | &"add"))
    {
        return false;
    }
    tokens[2..]
        .iter()
        .filter(|token| !token.starts_with('-'))
        .any(|token| !token.contains('@') && !token.contains('#') && !token.contains("://"))
}

pub(crate) fn regex_pattern_text<'a>(literal: &'a RegExpLiteral<'a>) -> &'a str {
    literal.regex.pattern.text.as_str()
}

/// Callee name for sink checks: plain identifier or last static member link
/// (`crypto.createHash` -> `createHash`).
pub(crate) fn sink_callee_name<'a>(callee: &'a Expression<'_>) -> Option<&'a str> {
    match callee {
        Expression::Identifier(identifier) => Some(&identifier.name),
        Expression::StaticMemberExpression(member) => Some(&member.property.name),
        _ => None,
    }
}

/// Normalized key name for duplicate detection: static identifiers plus
/// their quoted-string spellings (`{a: 1, "a": 2}` collide).
pub(crate) fn duplicated_key_name<'data>(key: &PropertyKey<'data>) -> Option<&'data str> {
    match key {
        PropertyKey::StaticIdentifier(identifier) => Some(identifier.name.as_str()),
        PropertyKey::StringLiteral(literal) => Some(literal.value.as_str()),
        _ => None,
    }
}

/// Whether a member chain passes through a `this.<link>` access.
pub(crate) fn expression_through_this_link(expression: &Expression<'_>, link: &str) -> bool {
    match expression {
        Expression::StaticMemberExpression(member) => {
            (matches!(&member.object, Expression::ThisExpression(_))
                && member.property.name == link)
                || expression_through_this_link(&member.object, link)
        }
        Expression::ComputedMemberExpression(member) => {
            expression_through_this_link(&member.object, link)
        }
        Expression::PrivateFieldExpression(member) => {
            expression_through_this_link(&member.object, link)
        }
        _ => false,
    }
}

/// Whether a statement terminates unconditionally for `S128`: a direct
/// jump, a block whose last statement jumps, or an `if/else` where both
/// branches jump.
pub(crate) fn statement_ends_with_jump(stmt: &Statement<'_>) -> bool {
    match stmt {
        Statement::BreakStatement(_)
        | Statement::ContinueStatement(_)
        | Statement::ReturnStatement(_)
        | Statement::ThrowStatement(_) => true,
        Statement::BlockStatement(block) => block.body.last().is_some_and(statement_ends_with_jump),
        Statement::IfStatement(if_statement) => {
            statement_ends_with_jump(&if_statement.consequent)
                && if_statement
                    .alternate
                    .as_ref()
                    .is_some_and(statement_ends_with_jump)
        }
        _ => false,
    }
}

pub(crate) fn static_command_text(expression: &Expression<'_>) -> Option<String> {
    match expression {
        Expression::StringLiteral(literal) => Some(literal.value.to_string()),
        Expression::TemplateLiteral(template) if template.expressions.is_empty() => Some(
            template
                .quasis
                .iter()
                .map(|quasi| quasi.value.raw.to_string())
                .collect(),
        ),
        _ => None,
    }
}

pub(crate) fn argument_expression<'r, 'a>(
    argument: &'r oxc_ast::ast::Argument<'a>,
) -> Option<&'r Expression<'a>> {
    argument.as_expression()
}

pub(crate) fn call_property<'r, 'a>(
    call: &'r CallExpression<'a>,
) -> Option<(&'r str, &'r MemberExpression<'a>)> {
    let member = call.callee.as_member_expression()?;
    let property = static_property_name(member)?;
    Some((property, member))
}
