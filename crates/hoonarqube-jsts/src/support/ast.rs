use oxc_ast::ast::{
    AssignmentTarget, BindingPattern, CallExpression, Expression, MemberExpression,
    ModuleExportName, NewExpression, PropertyKey, SimpleAssignmentTarget, Statement,
    UpdateExpression,
};

/// `Expression::Identifier` name, if the expression is a plain identifier.
pub(crate) fn identifier_name<'a>(expression: &'a Expression<'_>) -> Option<&'a str> {
    match expression {
        Expression::Identifier(identifier) => Some(&identifier.name),
        _ => None,
    }
}

/// Name of a plain-identifier callee.
pub(crate) fn callee_name<'a>(call: &'a CallExpression<'_>) -> Option<&'a str> {
    identifier_name(&call.callee)
}

/// Name of a plain-identifier constructor callee.
pub(crate) fn constructor_name<'a>(new: &'a NewExpression<'_>) -> Option<&'a str> {
    identifier_name(&new.callee)
}

/// Property name of a static member access (`a.b`), if any.
pub(crate) fn static_property_name<'data>(member: &MemberExpression<'data>) -> Option<&'data str> {
    match member {
        MemberExpression::StaticMemberExpression(static_member) => {
            Some(static_member.property.name.as_str())
        }
        _ => None,
    }
}

/// Root identifier of a member chain (`a` in `a.b.c`), if any.
pub(crate) fn member_root_name<'a>(member: &'a MemberExpression<'_>) -> Option<&'a str> {
    expression_root_name(member_object(member))
}

/// Root identifier of an expression chain, if any.
pub(crate) fn expression_root_name<'a>(expression: &'a Expression<'a>) -> Option<&'a str> {
    match expression {
        Expression::Identifier(identifier) => Some(&identifier.name),
        Expression::StaticMemberExpression(nested) => expression_root_name(&nested.object),
        Expression::ComputedMemberExpression(nested) => expression_root_name(&nested.object),
        Expression::PrivateFieldExpression(nested) => expression_root_name(&nested.object),
        _ => None,
    }
}

/// Whether the member chain starts at the given identifier.
pub(crate) fn member_rooted_at(member: &MemberExpression<'_>, root: &str) -> bool {
    member_root_name(member) == Some(root)
}

pub(crate) fn member_object<'r, 'a>(member: &'r MemberExpression<'a>) -> &'r Expression<'a> {
    match member {
        MemberExpression::StaticMemberExpression(static_member) => &static_member.object,
        MemberExpression::ComputedMemberExpression(computed_member) => &computed_member.object,
        MemberExpression::PrivateFieldExpression(private_field) => &private_field.object,
    }
}

pub(crate) fn property_key_name<'a>(key: &'a PropertyKey<'_>) -> Option<&'a str> {
    match key {
        PropertyKey::StaticIdentifier(identifier) => Some(&identifier.name),
        _ => None,
    }
}

/// Name of an import/export name, unless it is a string literal.
pub(crate) fn module_export_name_name<'a>(name: &'a ModuleExportName<'_>) -> Option<&'a str> {
    match name {
        ModuleExportName::IdentifierName(identifier) => Some(&identifier.name),
        ModuleExportName::IdentifierReference(identifier) => Some(&identifier.name),
        ModuleExportName::StringLiteral(_) => None,
    }
}

pub(crate) fn binding_identifier_name<'a>(pattern: &'a BindingPattern<'_>) -> Option<&'a str> {
    match pattern {
        BindingPattern::BindingIdentifier(identifier) => Some(&identifier.name),
        _ => None,
    }
}

/// Peels parenthesized wrappers; this parser preserves parentheses, so
/// `case (a(), b):` surfaces its sequence expression behind one.
pub(crate) fn unparenthesized<'a, 'b>(expression: &'a Expression<'b>) -> &'a Expression<'b> {
    let mut current = expression;
    while let Expression::ParenthesizedExpression(parenthesized) = current {
        current = &parenthesized.expression;
    }
    current
}

/// Name bound by an assignment target, if it is a plain identifier.
pub(crate) fn assignment_target_name<'a>(target: &'a AssignmentTarget<'a>) -> Option<&'a str> {
    match target {
        AssignmentTarget::AssignmentTargetIdentifier(identifier) => Some(&identifier.name),
        _ => None,
    }
}

/// Name modified by an update expression (`++`/`--`), if plain.
pub(crate) fn update_target_name<'a>(update: &'a UpdateExpression<'a>) -> Option<&'a str> {
    match &update.argument {
        SimpleAssignmentTarget::AssignmentTargetIdentifier(identifier) => Some(&identifier.name),
        _ => None,
    }
}

pub(crate) fn statement_as_expression<'a>(
    statement: &'a Statement<'a>,
) -> Option<&'a Expression<'a>> {
    match statement {
        Statement::ExpressionStatement(expr) => Some(&expr.expression),
        _ => None,
    }
}
