use super::collectors::TsTypeCollector;
use crate::support::RuleScope;
use crate::support::unparenthesized;
use oxc_ast::ast::Expression;
use oxc_ast::ast::TSEnumDeclaration;
use oxc_ast::ast::UnaryOperator;
use oxc_span::GetSpan;

/// Value of one enum member initializer for the `S6578` duplicate check.
#[derive(PartialEq)]
pub(crate) enum EnumMemberValue {
    Number(f64),
    Text(String),
}

pub(crate) fn enum_initializer_is_literal(initializer: &Expression<'_>) -> bool {
    match unparenthesized(initializer) {
        Expression::NumericLiteral(_)
        | Expression::StringLiteral(_)
        | Expression::BigIntLiteral(_) => true,
        Expression::TemplateLiteral(template) => template.expressions.is_empty(),
        Expression::UnaryExpression(unary) => {
            unary.operator == UnaryOperator::UnaryNegation
                && matches!(
                    unparenthesized(&unary.argument),
                    Expression::NumericLiteral(_)
                )
        }
        _ => false,
    }
}

pub(crate) fn enum_member_value(initializer: &Expression<'_>) -> Option<EnumMemberValue> {
    match unparenthesized(initializer) {
        Expression::NumericLiteral(literal) => Some(EnumMemberValue::Number(literal.value)),
        Expression::StringLiteral(literal) => {
            Some(EnumMemberValue::Text(literal.value.to_string()))
        }
        Expression::UnaryExpression(unary) if unary.operator == UnaryOperator::UnaryNegation => {
            match unparenthesized(&unary.argument) {
                Expression::NumericLiteral(nested) => Some(EnumMemberValue::Number(-nested.value)),
                _ => None,
            }
        }
        _ => None,
    }
}

impl TsTypeCollector<'_, '_> {
    /// `S6550`, `S6572`, `S6578`, and `S6583` over one enum declaration.
    pub(crate) fn check_enum_members(&mut self, declaration: &TSEnumDeclaration<'_>) {
        let members = &declaration.body.members;
        for member in members {
            if let Some(initializer) = &member.initializer
                && !enum_initializer_is_literal(initializer)
            {
                self.sink.emit_span(
                    RuleScope::TsOnly,
                    "S6550",
                    "Replace this computed enum member value with a constant value.",
                    member.span(),
                );
            }
        }
        let initialized = members
            .iter()
            .filter(|member| member.initializer.is_some())
            .count();
        if initialized > 0 && initialized < members.len() {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S6572",
                "Either give every member of this enum an initializer or none of them.",
                declaration.id.span(),
            );
        }
        let mut seen_values: Vec<EnumMemberValue> = Vec::new();
        let mut saw_number = false;
        let mut saw_text = false;
        for member in members {
            let Some(value) = member.initializer.as_ref().and_then(enum_member_value) else {
                continue;
            };
            saw_number |= matches!(value, EnumMemberValue::Number(_));
            saw_text |= matches!(value, EnumMemberValue::Text(_));
            if seen_values.contains(&value) {
                self.sink.emit_span(
                    RuleScope::TsOnly,
                    "S6578",
                    "Change or remove this duplicate value.",
                    member.span(),
                );
            } else {
                seen_values.push(value);
            }
        }
        if saw_number && saw_text {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S6583",
                "Mixing number and string values in this enum hurts readability.",
                declaration.id.span(),
            );
        }
    }
}
