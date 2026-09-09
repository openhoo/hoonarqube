use super::collectors::TsTypeCollector;
use crate::support::RuleScope;
use oxc_ast::ast::{
    BinaryOperator, BindingPattern, Expression, FormalParameters, FunctionBody, Statement,
    TSThisParameter, TSType, TSTypeAnnotation, TSTypeName,
};
use oxc_span::GetSpan;

impl TsTypeCollector<'_, '_> {
    /// `S4322`, `S4324`, and `S6565` over one function return type.
    pub(crate) fn check_return_type_annotations(
        &mut self,
        params: &FormalParameters<'_>,
        return_type: Option<&TSTypeAnnotation<'_>>,
        this_param: Option<&TSThisParameter<'_>>,
        body: Option<&FunctionBody<'_>>,
        id: Option<&oxc_ast::ast::BindingIdentifier<'_>>,
    ) {
        let parameter = this_param
            .is_none()
            .then(|| reference_parameter(params))
            .flatten();
        if let Some(return_type) = return_type {
            self.check_explicit_return_type(return_type, parameter);
            return;
        }
        self.check_inferred_return_type(parameter, body, id);
    }

    fn check_explicit_return_type(
        &mut self,
        return_type: &TSTypeAnnotation<'_>,
        parameter: Option<(&str, bool)>,
    ) {
        if let (Some((param_name, rest)), true) = (
            parameter,
            matches!(return_type.type_annotation, TSType::TSBooleanKeyword(_)),
        ) {
            let predicate_name = if rest {
                format!("{param_name}[0]")
            } else {
                param_name.to_owned()
            };
            let message = format!(
                "Use a type predicate ('{predicate_name} is T') instead of this boolean return type."
            );
            self.sink
                .emit_span(RuleScope::TsOnly, "S4322", &message, return_type.span());
        }
        if let TSType::TSTypeReference(reference) = &return_type.type_annotation {
            if let TSTypeName::IdentifierReference(identifier) = &reference.type_name
                && WRAPPER_TYPE_NAMES.contains(&identifier.name.as_str())
            {
                self.sink.emit_span(
                    RuleScope::TsOnly,
                    "S4324",
                    "Use the primitive type keyword instead of this wrapper object type.",
                    reference.span(),
                );
            }
            let enclosing_class = self.class_stack.last();
            if let (Some(class_name), TSTypeName::IdentifierReference(identifier)) =
                (enclosing_class, &reference.type_name)
                && class_name.as_str() == identifier.name.as_str()
            {
                self.sink.emit_span(
                    RuleScope::TsOnly,
                    "S6565",
                    "Return 'this' instead of the class name type.",
                    reference.span(),
                );
            }
        }
    }

    fn check_inferred_return_type(
        &mut self,
        parameter: Option<(&str, bool)>,
        body: Option<&FunctionBody<'_>>,
        id: Option<&oxc_ast::ast::BindingIdentifier<'_>>,
    ) {
        let Some((param_name, _)) = parameter else {
            return;
        };
        let Some(function_id) = id else {
            return;
        };
        let Some(body) = body else {
            return;
        };
        if !body_returns_guarded_cast(body, param_name) {
            return;
        }
        let message = format!(
            "Use a type predicate ('{param_name} is T') instead of an inferred boolean return type."
        );
        self.sink
            .emit_span(RuleScope::TsOnly, "S4322", &message, function_id.span);
    }
}

/// `S4322` helper: one reference-typed parameter or one reference-typed rest
/// parameter. The boolean indicates that the parameter is rest-shaped.
fn reference_parameter<'a>(params: &FormalParameters<'a>) -> Option<(&'a str, bool)> {
    if params.items.len() == 1 && params.rest.is_none() {
        let parameter = params.items.first()?;
        let annotation = parameter.type_annotation.as_ref()?;
        let TSType::TSTypeReference(reference) = &annotation.type_annotation else {
            return None;
        };
        let TSTypeName::IdentifierReference(_) = &reference.type_name else {
            return None;
        };
        let BindingPattern::BindingIdentifier(binding) = &parameter.pattern else {
            return None;
        };
        return Some((binding.name.as_str(), false));
    }
    if params.items.is_empty() {
        let rest = params.rest.as_ref()?;
        let annotation = rest.type_annotation.as_ref()?;
        let TSType::TSArrayType(array) = &annotation.type_annotation else {
            return None;
        };
        let TSType::TSTypeReference(reference) = &array.element_type else {
            return None;
        };
        let TSTypeName::IdentifierReference(_) = &reference.type_name else {
            return None;
        };
        let BindingPattern::BindingIdentifier(binding) = &rest.rest.argument else {
            return None;
        };
        return Some((binding.name.as_str(), true));
    }
    None
}

fn body_returns_guarded_cast(body: &FunctionBody<'_>, parameter_name: &str) -> bool {
    let [Statement::ReturnStatement(return_statement)] = body.statements.as_slice() else {
        return false;
    };
    let Some(argument) = return_statement.argument.as_ref() else {
        return false;
    };
    let Some((cast_expression, cast_type)) = guarded_cast(argument) else {
        return false;
    };
    if matches!(cast_type, TSType::TSAnyKeyword(_)) {
        return false;
    }
    expression_uses_parameter(cast_expression, parameter_name)
}

fn guarded_cast<'a>(
    expression: &'a Expression<'a>,
) -> Option<(&'a Expression<'a>, &'a TSType<'a>)> {
    let expression = strip_parentheses(expression);
    let Expression::BinaryExpression(binary) = expression else {
        return None;
    };
    if !matches!(
        binary.operator,
        BinaryOperator::Inequality | BinaryOperator::StrictInequality
    ) {
        return None;
    }
    if is_undefined(&binary.right) {
        cast_from_member(&binary.left)
    } else if is_undefined(&binary.left) {
        cast_from_member(&binary.right)
    } else {
        None
    }
}

fn is_undefined(expression: &Expression<'_>) -> bool {
    matches!(
        strip_parentheses(expression),
        Expression::Identifier(identifier) if identifier.name == "undefined"
    )
}

fn cast_from_member<'a>(
    expression: &'a Expression<'a>,
) -> Option<(&'a Expression<'a>, &'a TSType<'a>)> {
    let member_object = match strip_parentheses(expression) {
        Expression::StaticMemberExpression(member) => &member.object,
        Expression::ComputedMemberExpression(member) => &member.object,
        _ => return None,
    };
    match strip_parentheses(member_object) {
        Expression::TSAsExpression(cast) => Some((&cast.expression, &cast.type_annotation)),
        Expression::TSTypeAssertion(cast) => Some((&cast.expression, &cast.type_annotation)),
        _ => None,
    }
}

fn expression_uses_parameter(expression: &Expression<'_>, parameter_name: &str) -> bool {
    match strip_parentheses(expression) {
        Expression::Identifier(identifier) => identifier.name == parameter_name,
        Expression::StaticMemberExpression(member) => {
            expression_uses_parameter(&member.object, parameter_name)
        }
        Expression::ComputedMemberExpression(member) => {
            expression_uses_parameter(&member.object, parameter_name)
        }
        _ => false,
    }
}

fn strip_parentheses<'a>(expression: &'a Expression<'a>) -> &'a Expression<'a> {
    match expression {
        Expression::ParenthesizedExpression(parenthesized) => {
            strip_parentheses(&parenthesized.expression)
        }
        _ => expression,
    }
}

/// `S4324`: wrapper object type names that must not appear in return types.
const WRAPPER_TYPE_NAMES: [&str; 5] = ["String", "Number", "Boolean", "Symbol", "BigInt"];
