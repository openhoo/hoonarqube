// Residual rule machinery for 'batch5' (extracted from lib.rs).
use super::collectors::TsTypeCollector;
use crate::rules::duplicate::collectors::is_literal_expression;
use crate::support::RuleScope;
use crate::support::unparenthesized;
use oxc_ast::ast::ArrayExpressionElement;
use oxc_ast::ast::Expression;
use oxc_ast::ast::ObjectPropertyKind;
use oxc_ast::ast::TSType;
use oxc_ast::ast::TSTypeAnnotation;
use oxc_ast::ast::TSTypeName;
use oxc_ast::ast::TSTypeOperatorOperator;
use oxc_ast::ast::VariableDeclarator;
use oxc_span::GetSpan;

/// `S6590` helper: is the annotation a readonly-shaped type?
fn annotation_is_readonly_shaped(annotation: &TSTypeAnnotation<'_>) -> bool {
    match &annotation.type_annotation {
        TSType::TSTypeOperatorType(operator) => {
            operator.operator == TSTypeOperatorOperator::Readonly
        }
        TSType::TSTypeReference(reference) => match &reference.type_name {
            TSTypeName::IdentifierReference(identifier) => identifier.name.starts_with("Readonly"),
            _ => false,
        },
        _ => false,
    }
}

/// `S6590` helper: array/object literal built only from literal members.
fn is_const_candidate(expression: &Expression<'_>) -> bool {
    let literal_element = |element: &ArrayExpressionElement<'_>| {
        matches!(
            element,
            ArrayExpressionElement::NumericLiteral(_)
                | ArrayExpressionElement::StringLiteral(_)
                | ArrayExpressionElement::BooleanLiteral(_)
        )
    };
    match unparenthesized(expression) {
        Expression::ArrayExpression(array) => array.elements.iter().all(literal_element),
        Expression::ObjectExpression(object) => {
            object.properties.iter().all(|property| match property {
                ObjectPropertyKind::ObjectProperty(prop) => is_literal_expression(&prop.value),
                ObjectPropertyKind::SpreadProperty(_) => false,
            })
        }
        _ => false,
    }
}

// Generated per-rule checks (moved out of traversal overrides).
impl TsTypeCollector<'_, '_> {
    /// `S6590` logic extracted from `visit_variable_declarator`.
    pub(crate) fn check_s6590_variable_declarator(&mut self, it: &VariableDeclarator<'_>) {
        if let (Some(annotation), Some(init)) = (&it.type_annotation, &it.init)
            && annotation_is_readonly_shaped(annotation)
            && is_const_candidate(init)
        {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S6590",
                "Use an as const assertion instead of a readonly annotation.",
                init.span(),
            );
        }
    }
}
