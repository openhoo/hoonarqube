use super::collectors::TsTypeCollector;
use crate::support::{RuleScope, source_slice};
use oxc_ast::ast::{
    BinaryOperator, BindingPattern, Expression, FormalParameters, FunctionBody, Statement,
    TSThisParameter, TSType, TSTypeAnnotation, TSTypeName, UnaryOperator,
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
            self.check_explicit_return_type(return_type, parameter, body);
            return;
        }
        self.check_inferred_return_type(parameter, body, id);
    }

    fn check_explicit_return_type(
        &mut self,
        return_type: &TSTypeAnnotation<'_>,
        parameter: Option<(&str, bool)>,
        body: Option<&FunctionBody<'_>>,
    ) {
        // `S4322` (upstream `S4322/rule.ts`) only suggests a type predicate
        // when the body returns a guarded cast on the parameter — a plain
        // boolean function over a reference-typed parameter is not a guard.
        if let (Some((param_name, rest)), true, Some(body)) = (
            parameter,
            matches!(return_type.type_annotation, TSType::TSBooleanKeyword(_)),
            body,
        ) && let Some((cast_expression, cast_type)) = returned_guarded_cast(body)
            && !matches!(cast_type, TSType::TSAnyKeyword(_))
            && expression_uses_parameter(cast_expression, param_name)
        {
            let predicate_name = if rest {
                format!("{param_name}[0]")
            } else {
                param_name.to_owned()
            };
            let casted_type = source_slice(self.source, cast_type.span());
            let message = format!(
                "Use a type predicate ('{predicate_name} is {casted_type}') instead of this boolean return type."
            );
            self.sink
                .emit_span(RuleScope::TsOnly, "S4322", &message, return_type.span());
        }
        if let TSType::TSTypeReference(reference) = &return_type.type_annotation {
            // `S4324`: wrapper object types must not appear in return types.
            // A name that resolves to a file-local declaration (e.g. a
            // project `class Symbol`) is a domain type, not the JS wrapper.
            if let TSTypeName::IdentifierReference(identifier) = &reference.type_name
                && WRAPPER_TYPE_NAMES.contains(&identifier.name.as_str())
                && !self.reference_resolves_locally(identifier)
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

    /// Whether a type-name identifier resolves to a declaration in this file
    /// (any local binding shadows the global wrapper type name).
    fn reference_resolves_locally(
        &self,
        identifier: &oxc_ast::ast::IdentifierReference<'_>,
    ) -> bool {
        let Some(semantic) = self.semantic else {
            return false;
        };
        identifier
            .reference_id
            .get()
            .and_then(|id| semantic.scoping().get_reference(id).symbol_id())
            .is_some()
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
        let Some(casted_type) = body_returns_guarded_cast(body, param_name) else {
            return;
        };
        let casted_type = source_slice(self.source, casted_type.span());
        let message = format!(
            "Use a type predicate ('{param_name} is {casted_type}') instead of an inferred boolean return type."
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
fn body_returns_guarded_cast<'a>(
    body: &'a FunctionBody<'a>,
    parameter_name: &str,
) -> Option<&'a TSType<'a>> {
    let (cast_expression, cast_type) = returned_guarded_cast(body)?;
    if matches!(cast_type, TSType::TSAnyKeyword(_)) {
        return None;
    }
    expression_uses_parameter(cast_expression, parameter_name).then_some(cast_type)
}

/// The `(casted expression, casted type)` pair when the body is a single
/// `return` of a guarded cast: `(x as T).member !== undefined`,
/// `Boolean((x as T).member)`, or `!!(x as T).member`.
fn returned_guarded_cast<'a>(
    body: &'a FunctionBody<'a>,
) -> Option<(&'a Expression<'a>, &'a TSType<'a>)> {
    let [Statement::ReturnStatement(return_statement)] = body.statements.as_slice() else {
        return None;
    };
    guarded_cast(return_statement.argument.as_ref()?)
}

fn guarded_cast<'a>(
    expression: &'a Expression<'a>,
) -> Option<(&'a Expression<'a>, &'a TSType<'a>)> {
    let expression = strip_parentheses(expression);
    match expression {
        Expression::BinaryExpression(binary)
            if matches!(
                binary.operator,
                BinaryOperator::Inequality | BinaryOperator::StrictInequality
            ) =>
        {
            if is_undefined(&binary.right) {
                cast_from_member(&binary.left)
            } else if is_undefined(&binary.left) {
                cast_from_member(&binary.right)
            } else {
                None
            }
        }
        Expression::CallExpression(call)
            if call.arguments.len() == 1
                && matches!(
                    &call.callee,
                    Expression::Identifier(callee) if callee.name == "Boolean"
                ) =>
        {
            cast_from_member(call.arguments.first()?.as_expression()?)
        }
        Expression::UnaryExpression(outer)
            if outer.operator == UnaryOperator::LogicalNot
                && matches!(
                    strip_parentheses(&outer.argument),
                    Expression::UnaryExpression(inner)
                        if inner.operator == UnaryOperator::LogicalNot
                ) =>
        {
            let Expression::UnaryExpression(inner) = strip_parentheses(&outer.argument) else {
                return None;
            };
            cast_from_member(&inner.argument)
        }
        _ => None,
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

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn guarded_casts_suggest_type_predicates() {
        // Issue #514: only a body that narrows the parameter through a
        // guarded cast suggests a type predicate.
        let guarded = ts_keys(
            "type Foo = { kind?: string };\nfunction isFoo(x: Foo): boolean {\n  return (x as Foo).kind !== undefined;\n}\n",
        );
        assert_eq!(count_key(&guarded, "typescript:S4322"), 1);

        let boolean_call = ts_keys(
            "type Foo = { kind?: string };\nfunction isFoo(x: Foo): boolean {\n  return Boolean((x as Foo).kind);\n}\n",
        );
        assert_eq!(count_key(&boolean_call, "typescript:S4322"), 1);

        let double_negation = ts_keys(
            "type Foo = { kind?: string };\nfunction isFoo(x: Foo): boolean {\n  return !!(x as Foo).kind;\n}\n",
        );
        assert_eq!(count_key(&double_negation, "typescript:S4322"), 1);
    }

    #[test]
    fn non_guard_boolean_functions_stay_silent() {
        // Issue #514: membership/state predicates are not type guards.
        let repro = ts_keys(
            "interface Path { pos: number; end: number }\nclass Cache {\n    private cache = new Map<string, number>();\n    has(path: Path): boolean {\n        return this.cache.has(String(path.pos));\n    }\n}\nclass Program { active = true; }\nclass Session {\n    private isProgramActive(program: Program): boolean {\n        return program.active;\n    }\n}\nexport { Cache, Session };\n",
        );
        assert_eq!(count_key(&repro, "typescript:S4322"), 0);

        let constant = ts_keys("function isFoo(x: Foo): boolean { return true; }\n");
        assert_eq!(count_key(&constant, "typescript:S4322"), 0);
    }

    #[test]
    fn wrapper_return_types_are_flagged() {
        let violating = ts_keys("function f(): Number { return 1; }\n");
        assert_eq!(count_key(&violating, "typescript:S4324"), 1);

        let clean = ts_keys("function f(): number { return 1; }\n");
        assert_eq!(count_key(&clean, "typescript:S4324"), 0);
    }

    #[test]
    fn local_wrapper_named_types_stay_silent() {
        // Issue #531: a project-local `Symbol` class is a domain type.
        let local = ts_keys(
            "declare class Symbol { id: number }\ndeclare const data: { id: number };\nfunction getOrCreateSymbol(d: typeof data): Symbol {\n    return new Symbol();\n}\nexport { getOrCreateSymbol };\n",
        );
        assert_eq!(count_key(&local, "typescript:S4324"), 0);

        let imported = ts_keys(
            "import { String } from './strings.js';\nfunction f(): String { return make(); }\ndeclare function make(): String;\n",
        );
        assert_eq!(count_key(&imported, "typescript:S4324"), 0);
    }
}
