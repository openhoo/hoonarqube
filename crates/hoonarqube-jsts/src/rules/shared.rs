// Helpers shared across rule families (hoisted from rule-specific modules).
use crate::support::static_property_name;
use oxc_ast::ast::{
    BinaryOperator, BlockStatement, CallExpression, Class, Expression, JSXAttribute,
    JSXAttributeItem, JSXAttributeName, JSXElementName, JSXOpeningElement, MemberExpression,
    PropertyKey, RegExpLiteral, Statement, SwitchStatement, TryStatement,
};

/// `console` members flagged by `S106`.
pub(crate) const CONSOLE_METHODS: [&str; 8] = [
    "log", "info", "warn", "error", "debug", "trace", "dir", "table",
];

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

/// Whether a class extends the built-in React component bases:
/// `Component`/`PureComponent` or `React.Component`/`React.PureComponent`
/// (`S6435`/`S6441`/`S6746` provenance gate; non-React classes with
/// similarly named methods are never components).
pub(crate) fn is_builtin_react_superclass(class: &Class<'_>) -> bool {
    let Some(heritage) = &class.heritage else {
        return false;
    };
    match &heritage.expression {
        Expression::Identifier(identifier) => {
            matches!(identifier.name.as_str(), "Component" | "PureComponent")
        }
        Expression::StaticMemberExpression(member) => {
            matches!(&member.object, Expression::Identifier(object) if object.name == "React")
                && matches!(member.property.name.as_str(), "Component" | "PureComponent")
        }
        _ => false,
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

/// Whether a statement never completes normally for `S128`/`S1763`/`S3801`:
/// a direct jump, a block containing a jump, an `if/else` where both
/// branches jump, a `switch` with a `default` whose every case jumps, or a
/// `try` whose `try`/`catch`/`finally` arms all jump.
pub(crate) fn statement_ends_with_jump(stmt: &Statement<'_>) -> bool {
    match stmt {
        Statement::BreakStatement(_)
        | Statement::ContinueStatement(_)
        | Statement::ReturnStatement(_)
        | Statement::ThrowStatement(_) => true,
        Statement::BlockStatement(block) => block.body.iter().any(statement_ends_with_jump),
        Statement::IfStatement(if_statement) => {
            statement_ends_with_jump(&if_statement.consequent)
                && if_statement
                    .alternate
                    .as_ref()
                    .is_some_and(statement_ends_with_jump)
        }
        Statement::SwitchStatement(switch) => switch_never_completes(switch),
        Statement::TryStatement(try_statement) => try_never_completes(try_statement),
        _ => false,
    }
}

/// Whether a `switch` can never complete normally: some `default` case
/// covers the no-match path, no case body breaks out of the switch, and
/// the last case (the fall-through sink) ends in a jump.
fn switch_never_completes(switch: &SwitchStatement<'_>) -> bool {
    let has_default = switch.cases.iter().any(|case| case.test.is_none());
    let last_jumps = switch
        .cases
        .last()
        .is_some_and(|case| case.consequent.iter().any(statement_ends_with_jump));
    let may_break = switch
        .cases
        .iter()
        .any(|case| case.consequent.iter().any(statement_may_break_switch));
    has_default && last_jumps && !may_break
}

/// Whether a `try` can never complete normally: a `finally` that never
/// completes dominates; otherwise both the `try` block and the `catch`
/// handler (when present) must never complete.
fn try_never_completes(try_statement: &TryStatement<'_>) -> bool {
    let block_never = |block: &BlockStatement<'_>| block.body.iter().any(statement_ends_with_jump);
    if try_statement
        .finalizer
        .as_ref()
        .is_some_and(|finalizer| block_never(finalizer))
    {
        return true;
    }
    block_never(&try_statement.block)
        && try_statement
            .handler
            .as_ref()
            .is_none_or(|handler| block_never(&handler.body))
}

/// Whether a statement inside a `switch` case may break out of that switch:
/// any `break`/`continue` not shielded by a nested loop, switch, or
/// function boundary. Labeled jumps count conservatively — without label
/// resolution they may target the switch itself.
fn statement_may_break_switch(stmt: &Statement<'_>) -> bool {
    match stmt {
        Statement::BreakStatement(_) | Statement::ContinueStatement(_) => true,
        Statement::BlockStatement(block) => block.body.iter().any(statement_may_break_switch),
        Statement::IfStatement(if_statement) => {
            statement_may_break_switch(&if_statement.consequent)
                || if_statement
                    .alternate
                    .as_ref()
                    .is_some_and(statement_may_break_switch)
        }
        Statement::TryStatement(try_statement) => {
            try_statement
                .block
                .body
                .iter()
                .any(statement_may_break_switch)
                || try_statement
                    .handler
                    .as_ref()
                    .is_some_and(|handler| handler.body.body.iter().any(statement_may_break_switch))
                || try_statement
                    .finalizer
                    .as_ref()
                    .is_some_and(|finalizer| finalizer.body.iter().any(statement_may_break_switch))
        }
        _ => false,
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

/// Tag name of a JSX element when spelled as a plain identifier (`div`,
/// `Widget`); namespaced, member, and `this` names have none.
pub(crate) fn jsx_element_tag<'a>(name: &'a JSXElementName<'a>) -> Option<&'a str> {
    match name {
        JSXElementName::Identifier(identifier) => Some(identifier.name.as_str()),
        JSXElementName::IdentifierReference(reference) => Some(&reference.name),
        _ => None,
    }
}

/// Whether a tag starts lowercase (intrinsic HTML/SVG spelling).
pub(crate) fn jsx_tag_is_intrinsic(tag: &str) -> bool {
    tag.starts_with(|ch: char| ch.is_ascii_lowercase())
}

/// First attribute with the given name on an opening tag, if any.
pub(crate) fn jsx_find_attribute<'a>(
    opening: &'a JSXOpeningElement<'a>,
    name: &str,
) -> Option<&'a JSXAttribute<'a>> {
    opening.attributes.iter().find_map(|item| match item {
        JSXAttributeItem::Attribute(attribute) if jsx_attribute_name(attribute) == Some(name) => {
            Some(&**attribute)
        }
        _ => None,
    })
}

/// Tag name of a JSX attribute (`ref`, `children`, ...); namespaced names
/// (`xlink:href`) have no plain name.
pub(crate) fn jsx_attribute_name<'a>(attribute: &'a JSXAttribute<'a>) -> Option<&'a str> {
    match &attribute.name {
        JSXAttributeName::Identifier(identifier) => Some(identifier.name.as_str()),
        JSXAttributeName::NamespacedName(_) => None,
    }
}
