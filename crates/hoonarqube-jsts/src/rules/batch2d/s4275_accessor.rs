use super::collectors::{
    ClassAccessorCollector, accessor_has_matching_field, accessor_names_field,
};
use crate::support::RuleScope;
use oxc_ast::ast::{Expression, FunctionBody, SimpleAssignmentTarget, Statement};
use oxc_span::Span;
use std::collections::BTreeSet;

impl ClassAccessorCollector<'_> {
    /// `S4275`: accessors should touch the field their name declares. A
    /// finding requires a same-named data field to exist (field-existence
    /// gate) plus a single-statement body whose `this.<field>` reference
    /// points elsewhere; derived and multi-statement accessors are never
    /// suspects.
    pub(crate) fn check_accessor(
        &mut self,
        name: Option<&str>,
        key_span: Span,
        is_setter: bool,
        body: Option<&FunctionBody<'_>>,
        fields: &BTreeSet<String>,
    ) {
        let (Some(name), Some(body)) = (name, body) else {
            return;
        };
        if !accessor_has_matching_field(name, fields) {
            return;
        }
        if body.statements.len() != 1 {
            return;
        }
        let statement = &body.statements[0];
        let used_field = match (is_setter, statement) {
            (true, Statement::ExpressionStatement(expression_statement)) => {
                match &expression_statement.expression {
                    Expression::AssignmentExpression(assignment) => {
                        match assignment.left.as_simple_assignment_target() {
                            Some(SimpleAssignmentTarget::StaticMemberExpression(member)) => {
                                matches!(&member.object, Expression::ThisExpression(_))
                                    .then(|| member.property.name.as_str())
                            }
                            _ => None,
                        }
                    }
                    _ => None,
                }
            }
            (false, Statement::ReturnStatement(return_statement)) => return_statement
                .argument
                .as_ref()
                .and_then(this_static_property_name),
            _ => None,
        };
        let Some(used_field) = used_field else {
            return;
        };
        if accessor_names_field(name, used_field) {
            return;
        }
        let message = if is_setter {
            format!("Verify that this setter assigns the \"{name}\" field.")
        } else {
            format!("Verify that this getter accesses the \"{name}\" field.")
        };
        self.sink
            .emit_span(RuleScope::Both, "S4275", &message, key_span);
    }
}

/// Name of a direct `this.<field>` member expression (`S4275`); member
/// chains, computed accessors, and non-`this` receivers have none.
fn this_static_property_name<'a>(expression: &'a Expression<'a>) -> Option<&'a str> {
    match expression {
        Expression::StaticMemberExpression(member) => {
            matches!(&member.object, Expression::ThisExpression(_))
                .then(|| member.property.name.as_str())
        }
        _ => None,
    }
}
