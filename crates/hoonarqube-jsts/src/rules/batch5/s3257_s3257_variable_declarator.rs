use super::collectors::TsTypeCollector;
use crate::support::{RuleScope, source_slice, unparenthesized};
use oxc_ast::ast::{
    AccessorProperty, Expression, FormalParameter, PropertyDefinition, TSType, TSTypeName,
    UnaryOperator, VariableDeclarator,
};
use oxc_span::GetSpan;

// `S3257` mirrors `typescript-eslint/no-inferrable-types`: an annotation is
// flagged only when the initializer is trivially inferable (a literal, a
// direct wrapper call such as `String(..)`, or a `!`/`void`/`+`/`-` prefix
// form). Non-literal initializers such as `value ?? fallback` stay silent.
impl TsTypeCollector<'_, '_> {
    /// `S3257` logic extracted from `visit_variable_declarator`.
    pub(crate) fn check_s3257_variable_declarator(&mut self, it: &VariableDeclarator<'_>) {
        if let Some(annotation) = &it.type_annotation
            && let Some(init) = &it.init
            && init_is_inferrable(&annotation.type_annotation, init)
        {
            self.emit_s3257(annotation, it.id.span().start, init.span().end);
        }
    }

    /// `S3257` on class property declarations (`x: boolean = false`).
    ///
    /// `readonly` and optional properties are exempt: stripping their
    /// annotation changes the inferred property type (Microsoft/TypeScript#14416).
    pub(crate) fn check_s3257_property_definition(&mut self, it: &PropertyDefinition<'_>) {
        if it.readonly || it.optional {
            return;
        }
        if let Some(annotation) = &it.type_annotation
            && let Some(value) = &it.value
            && init_is_inferrable(&annotation.type_annotation, value)
        {
            self.emit_s3257(annotation, it.key.span().start, value.span().end);
        }
    }

    /// `S3257` on `accessor` property declarations.
    pub(crate) fn check_s3257_accessor_property(&mut self, it: &AccessorProperty<'_>) {
        if let Some(annotation) = &it.type_annotation
            && let Some(value) = &it.value
            && init_is_inferrable(&annotation.type_annotation, value)
        {
            self.emit_s3257(annotation, it.key.span().start, value.span().end);
        }
    }

    /// `S3257` on default parameters (`x: number = 0`).
    pub(crate) fn check_s3257_formal_parameter(&mut self, it: &FormalParameter<'_>) {
        if let Some(annotation) = &it.type_annotation
            && let Some(init) = &it.initializer
            && init_is_inferrable(&annotation.type_annotation, init)
        {
            self.emit_s3257(annotation, it.pattern.span().start, init.span().end);
        }
    }

    fn emit_s3257(
        &mut self,
        annotation: &oxc_ast::ast::TSTypeAnnotation<'_>,
        start: u32,
        end: u32,
    ) {
        let inferred_type = source_slice(self.source, annotation.type_annotation.span());
        self.sink.emit_span(
            RuleScope::TsOnly,
            "S3257",
            &format!(
                "Type {inferred_type} trivially inferred from a {inferred_type} literal, remove type annotation."
            ),
            oxc_span::Span::new(start, end),
        );
    }
}

/// Whether `init` makes `annotation` trivially inferable, mirroring the
/// upstream `isInferrable` table.
fn init_is_inferrable(annotation: &TSType<'_>, init: &Expression<'_>) -> bool {
    let init = unparenthesized(init);
    match annotation {
        TSType::TSBigIntKeyword(_) => {
            let unwrapped = strip_unary_prefix(init, &[UnaryOperator::UnaryNegation]);
            is_function_call(unwrapped, "BigInt")
                || matches!(unwrapped, Expression::BigIntLiteral(_))
        }
        TSType::TSBooleanKeyword(_) => {
            has_unary_prefix(init, UnaryOperator::LogicalNot)
                || is_function_call(init, "Boolean")
                || matches!(init, Expression::BooleanLiteral(_))
        }
        TSType::TSNumberKeyword(_) => {
            let unwrapped = strip_unary_prefix(
                init,
                &[UnaryOperator::UnaryPlus, UnaryOperator::UnaryNegation],
            );
            matches!(unwrapped, Expression::NumericLiteral(_))
                || matches!(
                    unwrapped,
                    Expression::Identifier(id) if matches!(id.name.as_str(), "Infinity" | "NaN")
                )
                || is_function_call(unwrapped, "Number")
        }
        TSType::TSNullKeyword(_) => matches!(init, Expression::NullLiteral(_)),
        TSType::TSStringKeyword(_) => {
            matches!(
                init,
                Expression::StringLiteral(_) | Expression::TemplateLiteral(_)
            ) || is_function_call(init, "String")
        }
        TSType::TSSymbolKeyword(_) => is_function_call(init, "Symbol"),
        TSType::TSTypeReference(reference) => {
            matches!(&reference.type_name, TSTypeName::IdentifierReference(id) if id.name == "RegExp")
                && (matches!(init, Expression::RegExpLiteral(_))
                    || is_function_call(init, "RegExp")
                    || is_new_call(init, "RegExp"))
        }
        TSType::TSUndefinedKeyword(_) => {
            has_unary_prefix(init, UnaryOperator::Void)
                || matches!(init, Expression::Identifier(id) if id.name == "undefined")
        }
        _ => false,
    }
}

/// Whether `expression` is `operator operand` (e.g. `!x`, `void 0`).
fn has_unary_prefix(expression: &Expression<'_>, operator: UnaryOperator) -> bool {
    matches!(
        expression,
        Expression::UnaryExpression(unary) if unary.operator == operator
    )
}

/// Inner expression of `operator operand` when the operator matches.
fn strip_unary_prefix<'a>(
    expression: &'a Expression<'a>,
    operators: &[UnaryOperator],
) -> &'a Expression<'a> {
    match expression {
        Expression::UnaryExpression(unary) if operators.contains(&unary.operator) => {
            unparenthesized(&unary.argument)
        }
        _ => expression,
    }
}

/// Whether `expression` is a direct call `name(..)` on a bare identifier.
fn is_function_call(expression: &Expression<'_>, name: &str) -> bool {
    match expression {
        Expression::CallExpression(call) => matches!(
            &call.callee,
            Expression::Identifier(id) if id.name == name
        ),
        _ => false,
    }
}

/// Whether `expression` is a direct `new Name(..)` on a bare identifier.
fn is_new_call(expression: &Expression<'_>, name: &str) -> bool {
    match expression {
        Expression::NewExpression(new_expr) => matches!(
            &new_expr.callee,
            Expression::Identifier(id) if id.name == name
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn literal_initializers_are_flagged() {
        let violating = ts_keys("const X: number = 1;\nlet y: string = 'a';\n");
        assert_eq!(count_key(&violating, "typescript:S3257"), 2);

        let without_initializer = ts_keys("let y: string;\n");
        assert_eq!(count_key(&without_initializer, "typescript:S3257"), 0);

        let non_primitive = ts_keys("const P: Point = { x: 1, y: 2 };\n");
        assert_eq!(count_key(&non_primitive, "typescript:S3257"), 0);
    }

    #[test]
    fn non_literal_initializers_stay_silent() {
        // Issue #479: `??` expressions are not trivially-inferable literals.
        let nullish = ts_keys(
            "function f(tmpl: { text?: string; rawText?: string; templateFlags?: number }): void {\n  const text: string = tmpl.text ?? \"\";\n  const rawText: string = tmpl.rawText ?? \"\";\n  const templateFlags: number = tmpl.templateFlags ?? 0;\n}\n",
        );
        assert_eq!(count_key(&nullish, "typescript:S3257"), 0);

        let member = ts_keys("declare const o: { v: number };\nconst n: number = o.v;\n");
        assert_eq!(count_key(&member, "typescript:S3257"), 0);

        let binary = ts_keys("declare const a: number;\nconst n: number = a + 1;\n");
        assert_eq!(count_key(&binary, "typescript:S3257"), 0);
    }

    #[test]
    fn inferrable_wrapper_calls_and_prefix_forms_are_flagged() {
        let calls = ts_keys(
            "const s: string = String(x);\nconst n: number = Number(x);\nconst b: boolean = Boolean(x);\n",
        );
        assert_eq!(count_key(&calls, "typescript:S3257"), 3);

        let prefixes = ts_keys(
            "declare const x: unknown;\nconst b: boolean = !x;\nconst n: number = -1;\nconst u: undefined = void 0;\n",
        );
        assert_eq!(count_key(&prefixes, "typescript:S3257"), 3);
    }

    #[test]
    fn property_declarations_and_default_parameters_are_flagged() {
        // Issue #480: property declarations and default parameters carry
        // trivially-inferable annotations too.
        let property = ts_keys("class C {\n  private initialized: boolean = false;\n}\n");
        assert_eq!(count_key(&property, "typescript:S3257"), 1);

        let parameter = ts_keys("function f(x: number = 0) { return x; }\n");
        assert_eq!(count_key(&parameter, "typescript:S3257"), 1);

        let parameter_property =
            ts_keys("class C {\n  constructor(private count: number = 0) {}\n}\n");
        assert_eq!(count_key(&parameter_property, "typescript:S3257"), 1);
    }

    #[test]
    fn property_exemptions_stay_silent() {
        // `readonly`/`optional` properties keep their annotation (upstream
        // exemption); a `??` initializer is not inferable either.
        let readonly = ts_keys("class C {\n  readonly tag: string = 'x';\n}\n");
        assert_eq!(count_key(&readonly, "typescript:S3257"), 0);

        let optional = ts_keys("class C {\n  tag?: string = 'x';\n}\n");
        assert_eq!(count_key(&optional, "typescript:S3257"), 0);

        let nullish_property =
            ts_keys("declare const o: { v: number };\nclass C {\n  n: number = o.v ?? 0;\n}\n");
        assert_eq!(count_key(&nullish_property, "typescript:S3257"), 0);
    }
}
