// Residual rule machinery for 'batch5' (extracted from lib.rs).
use crate::rules::duplicate::collectors::is_literal_expression;
use crate::rules::expression::s1528_constructor_calls::argument_expression;
use crate::rules::react_jsx::walker::duplicated_key_name;
use crate::support::{IssueSink, RuleScope, property_key_name, source_slice, unparenthesized};
use oxc_ast::ast::{
    ArrayExpressionElement, ArrowFunctionExpression, AssignmentExpression, AwaitExpression,
    CallExpression, Class, Expression, FormalParameter, FormalParameters, ImportDeclaration,
    LogicalExpression, LogicalOperator, MemberExpression, MethodDefinition, MethodDefinitionKind,
    NewExpression, ObjectExpression, ObjectProperty, ObjectPropertyKind, PropertyDefinition,
    Statement, StringLiteral, TSAccessibility, TSAnyKeyword, TSEnumDeclaration,
    TSInterfaceDeclaration, TSIntersectionType, TSLiteral, TSNamespaceDeclaration,
    TSNamespaceDeclarationKind, TSNonNullExpression, TSPropertySignature, TSSignature, TSType,
    TSTypeAliasDeclaration, TSTypeAnnotation, TSTypeAssertion, TSTypeLiteral, TSTypeName,
    TSTypeOperatorOperator, TSTypeParameter, TSUnionType, TemplateLiteral, UnaryOperator,
    VariableDeclarator,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_arrow_function_expression, walk_assignment_expression, walk_await_expression,
    walk_call_expression, walk_class, walk_formal_parameter, walk_import_declaration,
    walk_logical_expression, walk_member_expression, walk_method_definition, walk_new_expression,
    walk_object_property, walk_property_definition, walk_statement, walk_string_literal,
    walk_template_literal, walk_ts_any_keyword, walk_ts_enum_declaration,
    walk_ts_interface_declaration, walk_ts_intersection_type, walk_ts_namespace_declaration,
    walk_ts_non_null_expression, walk_ts_property_signature, walk_ts_type_alias_declaration,
    walk_ts_type_assertion, walk_ts_type_literal, walk_ts_type_parameter, walk_ts_union_type,
    walk_variable_declarator,
};
use oxc_span::{GetSpan, Span};

/// `S4622` catalog parameter `threshold` default: maximum union members.
pub(crate) const MAX_UNION_TYPE_MEMBERS: usize = 3;

/// Classification of one union/intersection constituent for the redundancy
/// checks `S6571` (keyword-level subsumption) and `S4621` (structural
/// equality).
pub(crate) enum Constituent {
    /// A keyword type (`string`, `number`, ...) with its canonical name.
    Keyword(&'static str),
    /// A literal type (`'a'`, `42`, `true`) with the primitive subsuming it.
    Literal(&'static str),
    /// Everything else (type references, object literals, ...).
    Other,
}

pub(crate) fn constituent_kind(ts_type: &TSType<'_>) -> Constituent {
    match ts_type {
        TSType::TSAnyKeyword(_) => Constituent::Keyword("any"),
        TSType::TSBigIntKeyword(_) => Constituent::Keyword("bigint"),
        TSType::TSBooleanKeyword(_) => Constituent::Keyword("boolean"),
        TSType::TSIntrinsicKeyword(_) => Constituent::Keyword("intrinsic"),
        TSType::TSNeverKeyword(_) => Constituent::Keyword("never"),
        TSType::TSNullKeyword(_) => Constituent::Keyword("null"),
        TSType::TSNumberKeyword(_) => Constituent::Keyword("number"),
        TSType::TSObjectKeyword(_) => Constituent::Keyword("object"),
        TSType::TSStringKeyword(_) => Constituent::Keyword("string"),
        TSType::TSSymbolKeyword(_) => Constituent::Keyword("symbol"),
        TSType::TSThisType(_) => Constituent::Keyword("this"),
        TSType::TSUndefinedKeyword(_) => Constituent::Keyword("undefined"),
        TSType::TSUnknownKeyword(_) => Constituent::Keyword("unknown"),
        TSType::TSVoidKeyword(_) => Constituent::Keyword("void"),
        TSType::TSLiteralType(literal) => match &literal.literal {
            TSLiteral::StringLiteral(_) => Constituent::Literal("string"),
            TSLiteral::NumericLiteral(_) | TSLiteral::UnaryExpression(_) => {
                Constituent::Literal("number")
            }
            TSLiteral::BooleanLiteral(_) => Constituent::Literal("boolean"),
            TSLiteral::BigIntLiteral(_) => Constituent::Literal("bigint"),
            TSLiteral::TemplateLiteral(_) => Constituent::Other,
        },
        _ => Constituent::Other,
    }
}

pub(crate) fn keyword_name(ts_type: &TSType<'_>) -> Option<&'static str> {
    match constituent_kind(ts_type) {
        Constituent::Keyword(name) => Some(name),
        _ => None,
    }
}

pub(crate) fn type_is_primitive_keyword(ts_type: &TSType<'_>) -> bool {
    matches!(
        ts_type,
        TSType::TSStringKeyword(_)
            | TSType::TSNumberKeyword(_)
            | TSType::TSBooleanKeyword(_)
            | TSType::TSBigIntKeyword(_)
            | TSType::TSSymbolKeyword(_)
            | TSType::TSUndefinedKeyword(_)
            | TSType::TSNullKeyword(_)
            | TSType::TSVoidKeyword(_)
            | TSType::TSNeverKeyword(_)
            | TSType::TSIntrinsicKeyword(_)
    )
}

pub(crate) fn type_is_objectish(ts_type: &TSType<'_>) -> bool {
    match ts_type {
        TSType::TSParenthesizedType(inner) => type_is_objectish(&inner.type_annotation),
        TSType::TSTypeLiteral(_)
        | TSType::TSArrayType(_)
        | TSType::TSTupleType(_)
        | TSType::TSFunctionType(_)
        | TSType::TSMappedType(_)
        | TSType::TSIndexedAccessType(_)
        | TSType::TSConstructorType(_)
        | TSType::TSImportType(_)
        | TSType::TSNamedTupleMember(_) => true,
        _ => false,
    }
}

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

pub(crate) struct TsTypeCollector<'s, 'index> {
    pub(crate) source: &'s str,
    pub(crate) sink: IssueSink<'index>,
    /// Enclosing class names, innermost last (`S6565`).
    pub(crate) class_stack: Vec<String>,
    /// Constructor nesting depth (`S7059`).
    pub(crate) constructor_depth: u32,
}

impl<'a> Visit<'a> for TsTypeCollector<'_, '_> {
    fn visit_ts_enum_declaration(&mut self, it: &TSEnumDeclaration<'a>) {
        self.check_enum_members(it);
        walk_ts_enum_declaration(self, it);
    }

    fn visit_ts_union_type(&mut self, it: &TSUnionType<'a>) {
        self.check_constituent_redundancy(&it.types, "union");
        if it.types.len() > MAX_UNION_TYPE_MEMBERS {
            let message = format!(
                "Reduce this union type; it currently has {} members.",
                it.types.len()
            );
            self.sink
                .emit_span(RuleScope::TsOnly, "S4622", &message, it.span());
        }
        walk_ts_union_type(self, it);
    }

    fn visit_ts_intersection_type(&mut self, it: &TSIntersectionType<'a>) {
        self.check_constituent_redundancy(&it.types, "intersection");
        if it.types.iter().any(type_is_primitive_keyword) && it.types.iter().any(type_is_objectish)
        {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S4335",
                "Review this intersection type; combining a primitive type with an object type is meaningless.",
                it.span(),
            );
        }
        walk_ts_intersection_type(self, it);
    }

    fn visit_ts_type_alias_declaration(&mut self, it: &TSTypeAliasDeclaration<'a>) {
        if let TSType::TSTypeReference(reference) = &it.type_annotation
            && reference.type_arguments.is_none()
        {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S6564",
                "Replace this alias with the type it references.",
                reference.span(),
            );
        }
        walk_ts_type_alias_declaration(self, it);
    }

    fn visit_ts_type_parameter(&mut self, it: &TSTypeParameter<'a>) {
        if let Some(constraint) = &it.constraint
            && matches!(
                constraint,
                TSType::TSAnyKeyword(_) | TSType::TSUnknownKeyword(_) | TSType::TSObjectKeyword(_)
            )
        {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S6569",
                "This constraint does not meaningfully restrict the type parameter; remove it.",
                constraint.span(),
            );
        }
        if let (Some(constraint), Some(default)) = (&it.constraint, &it.default)
            && self.source_slice_eq(constraint.span(), default.span())
        {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S4157",
                "Remove this redundant type parameter default; it repeats the constraint.",
                default.span(),
            );
        }
        walk_ts_type_parameter(self, it);
    }

    fn visit_ts_non_null_expression(&mut self, it: &TSNonNullExpression<'a>) {
        self.sink.emit_span(
            RuleScope::TsOnly,
            "S2966",
            "Remove this non-null assertion; it can hide null or undefined values.",
            it.span(),
        );
        walk_ts_non_null_expression(self, it);
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        if let Some(annotation) = &it.type_annotation
            && type_is_primitive_keyword(&annotation.type_annotation)
            && it.init.is_some()
        {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S3257",
                "Remove this redundant type annotation; the initializer already provides the type.",
                annotation.span(),
            );
        }
        if let Some(init) = &it.init
            && matches!(unparenthesized(init), Expression::ThisExpression(_))
        {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S4327",
                "Remove this assignment of 'this' to a variable; arrow functions keep the lexical 'this'.",
                it.span(),
            );
        }
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
        walk_variable_declarator(self, it);
    }

    fn visit_ts_type_assertion(&mut self, it: &TSTypeAssertion<'a>) {
        self.sink.emit_span(
            RuleScope::TsOnly,
            "S4137",
            "Use an as-prefixed assertion instead of this angle-bracket assertion.",
            it.span(),
        );
        walk_ts_type_assertion(self, it);
    }

    fn visit_ts_namespace_declaration(&mut self, it: &TSNamespaceDeclaration<'a>) {
        if it.kind == TSNamespaceDeclarationKind::Module {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S4156",
                "Prefer the namespace keyword over module for these declarations.",
                it.span(),
            );
        }
        walk_ts_namespace_declaration(self, it);
    }

    fn visit_ts_any_keyword(&mut self, it: &TSAnyKeyword) {
        self.sink.emit_span(
            RuleScope::TsOnly,
            "S4204",
            "Replace this any type with a more specific type.",
            it.span(),
        );
        walk_ts_any_keyword(self, it);
    }

    fn visit_ts_property_signature(&mut self, it: &TSPropertySignature<'a>) {
        if let Some(annotation) = &it.type_annotation
            && it.optional
            && union_contains_undefined(&annotation.type_annotation)
        {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S4782",
                "Remove the undefined member from this union; the property is already optional.",
                it.span(),
            );
        }
        walk_ts_property_signature(self, it);
    }

    fn visit_formal_parameter(&mut self, it: &FormalParameter<'a>) {
        if let Some(annotation) = &it.type_annotation
            && it.optional
            && it.initializer.is_none()
            && matches!(annotation.type_annotation, TSType::TSBooleanKeyword(_))
        {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S4798",
                "Provide a default value for this optional boolean parameter.",
                it.span(),
            );
        }
        walk_formal_parameter(self, it);
    }

    fn visit_ts_interface_declaration(&mut self, it: &TSInterfaceDeclaration<'a>) {
        self.check_single_call_signature(&it.body.body, it.span());
        self.check_overload_grouping(&it.body.body);
        if let [TSSignature::TSPropertySignature(_)] = it.body.body.as_slice() {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S4323",
                "Prefer declaring this single-property interface as a type alias.",
                it.span(),
            );
        }
        if it.id.name.contains("Props") {
            for member in &it.body.body {
                if let TSSignature::TSPropertySignature(property) = member
                    && !property.readonly
                {
                    self.sink.emit_span(
                        RuleScope::TsOnly,
                        "S6759",
                        "Add the readonly modifier to this property.",
                        property.span(),
                    );
                }
            }
        }
        walk_ts_interface_declaration(self, it);
    }

    fn visit_ts_type_literal(&mut self, it: &TSTypeLiteral<'a>) {
        self.check_single_call_signature(&it.members, it.span());
        self.check_overload_grouping(&it.members);
        walk_ts_type_literal(self, it);
    }

    fn visit_class(&mut self, it: &Class<'a>) {
        if let Some(id) = &it.id {
            self.class_stack.push(id.name.to_string());
        }
        walk_class(self, it);
        if it.id.is_some() {
            self.class_stack.pop();
        }
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        if it.kind == MethodDefinitionKind::Constructor {
            self.constructor_depth += 1;
            walk_method_definition(self, it);
            self.constructor_depth -= 1;
        } else {
            walk_method_definition(self, it);
        }
        self.check_return_type_annotations(&it.value.params, it.value.return_type.as_deref());
    }

    fn visit_statement(&mut self, it: &Statement<'a>) {
        if let Statement::FunctionDeclaration(function) = it {
            self.check_return_type_annotations(&function.params, function.return_type.as_deref());
        }
        walk_statement(self, it);
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        self.check_return_type_annotations(&it.params, it.return_type.as_deref());
        walk_arrow_function_expression(self, it);
    }

    fn visit_logical_expression(&mut self, it: &LogicalExpression<'a>) {
        if matches!(it.operator, LogicalOperator::Coalesce | LogicalOperator::Or) {
            for operand in [&it.left, &it.right] {
                if let Expression::TSNonNullExpression(assertion) = unparenthesized(operand) {
                    self.sink.emit_span(
                        RuleScope::TsOnly,
                        "S6568",
                        "Remove this unnecessary non-null assertion; the guard already handles null and undefined.",
                        assertion.span(),
                    );
                }
            }
        }
        walk_logical_expression(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        if self.constructor_depth > 0 && callee_is_async_function(&it.callee) {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S7059",
                "Move this asynchronous work out of the constructor.",
                it.span(),
            );
        }
        walk_call_expression(self, it);
    }

    fn visit_property_definition(&mut self, it: &PropertyDefinition<'a>) {
        if it.r#static
            && !it.readonly
            && !matches!(
                it.accessibility,
                Some(TSAccessibility::Private | TSAccessibility::Protected)
            )
        {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S1444",
                "Add the readonly modifier to this static property.",
                it.span(),
            );
        }
        walk_property_definition(self, it);
    }

    fn visit_await_expression(&mut self, it: &AwaitExpression<'a>) {
        if self.constructor_depth > 0 {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S7059",
                "Move this asynchronous work out of the constructor.",
                it.span(),
            );
        }
        if let Expression::AwaitExpression(inner) = unparenthesized(&it.argument) {
            self.sink.emit_span(
                RuleScope::Both,
                "S4326",
                "Remove this nested await; awaiting an awaited value is redundant.",
                inner.span(),
            );
        }
        walk_await_expression(self, it);
    }
}

impl TsTypeCollector<'_, '_> {
    /// `S6550`, `S6572`, `S6578`, and `S6583` over one enum declaration.
    fn check_enum_members(&mut self, declaration: &TSEnumDeclaration<'_>) {
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

    /// `S6571` keyword-level redundancy and `S4621` structural duplicates.
    fn check_constituent_redundancy(&mut self, types: &[TSType<'_>], container: &str) {
        let all_keywords: Vec<&'static str> = types.iter().filter_map(keyword_name).collect();
        let mut seen_keywords: Vec<&'static str> = Vec::new();
        let mut seen_slices: Vec<&str> = Vec::new();
        for ts_type in types {
            match constituent_kind(ts_type) {
                Constituent::Keyword(name) => {
                    if seen_keywords.contains(&name) {
                        let message =
                            format!("Remove this redundant member from the {container} type.");
                        self.sink
                            .emit_span(RuleScope::TsOnly, "S6571", &message, ts_type.span());
                    } else {
                        seen_keywords.push(name);
                    }
                }
                Constituent::Literal(base) => {
                    if all_keywords.contains(&base) {
                        let message =
                            format!("Remove this redundant member from the {container} type.");
                        self.sink
                            .emit_span(RuleScope::TsOnly, "S6571", &message, ts_type.span());
                    }
                }
                Constituent::Other => {
                    let text = source_slice(self.source, ts_type.span());
                    if seen_slices.contains(&text) {
                        self.sink.emit_span(
                            RuleScope::TsOnly,
                            "S4621",
                            "Remove this duplicated type member.",
                            ts_type.span(),
                        );
                    } else {
                        seen_slices.push(text);
                    }
                }
            }
        }
    }

    fn source_slice_eq(&self, left: Span, right: Span) -> bool {
        source_slice(self.source, left) == source_slice(self.source, right)
    }

    /// `S6598`: an interface or object type holding exactly one call
    /// signature should be declared as a function type instead.
    fn check_single_call_signature(&mut self, members: &[TSSignature<'_>], span: Span) {
        if let [TSSignature::TSCallSignatureDeclaration(_)] = members {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S6598",
                "Declare this type as a function type instead of wrapping a call signature.",
                span,
            );
        }
    }

    /// `S4136`: same-name method-signature overloads separated by unrelated
    /// signature kinds must be grouped together.
    fn check_overload_grouping(&mut self, members: &[TSSignature<'_>]) {
        let mut last_method_positions: Vec<(&str, usize)> = Vec::new();
        for (position, member) in members.iter().enumerate() {
            let TSSignature::TSMethodSignature(method) = member else {
                continue;
            };
            let Some(name) = property_key_name(&method.key) else {
                continue;
            };
            if let Some(entry) = last_method_positions
                .iter_mut()
                .find(|(seen_name, _)| *seen_name == name)
            {
                let previous = entry.1;
                if members[previous + 1..position]
                    .iter()
                    .any(|other| !matches!(other, TSSignature::TSMethodSignature(_)))
                {
                    self.sink.emit_span(
                        RuleScope::TsOnly,
                        "S4136",
                        "Group all overloaded signatures of this method together.",
                        method.span(),
                    );
                }
                entry.1 = position;
            } else {
                last_method_positions.push((name, position));
            }
        }
    }

    /// `S4322`, `S4324`, and `S6565` over one function return type.
    fn check_return_type_annotations(
        &mut self,
        params: &FormalParameters<'_>,
        return_type: Option<&TSTypeAnnotation<'_>>,
    ) {
        let Some(return_type) = return_type else {
            return;
        };
        if matches!(return_type.type_annotation, TSType::TSBooleanKeyword(_))
            && let Some(param_name) = single_reference_parameter(params)
        {
            let message = format!(
                "Use a type predicate ('{param_name} is T') instead of this boolean return type."
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
}

/// `S4782` helper: does the type union contain the `undefined` keyword?
pub(crate) fn union_contains_undefined(ts_type: &TSType<'_>) -> bool {
    match ts_type {
        TSType::TSUnionType(union) => union
            .types
            .iter()
            .any(|member| matches!(member, TSType::TSUndefinedKeyword(_))),
        _ => false,
    }
}

/// `S4324`: wrapper object type names that must not appear in return types.
pub(crate) const WRAPPER_TYPE_NAMES: [&str; 5] =
    ["String", "Number", "Boolean", "Symbol", "BigInt"];

/// `S4322` helper: name of the single reference-typed parameter, if any.
pub(crate) fn single_reference_parameter<'a>(params: &FormalParameters<'a>) -> Option<&'a str> {
    if params.items.len() != 1 {
        return None;
    }
    let annotation = params.items[0].type_annotation.as_ref()?;
    match &annotation.type_annotation {
        TSType::TSTypeReference(reference) => match &reference.type_name {
            TSTypeName::IdentifierReference(identifier) => Some(identifier.name.as_str()),
            _ => None,
        },
        _ => None,
    }
}

/// `S6590` helper: is the annotation a readonly-shaped type?
pub(crate) fn annotation_is_readonly_shaped(annotation: &TSTypeAnnotation<'_>) -> bool {
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
pub(crate) fn is_const_candidate(expression: &Expression<'_>) -> bool {
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

/// `S7059` helper: is the callee an async function/arrow expression?
pub(crate) fn callee_is_async_function(callee: &Expression<'_>) -> bool {
    match unparenthesized(callee) {
        Expression::ArrowFunctionExpression(arrow) => arrow.r#async,
        Expression::FunctionExpression(function) => function.r#async,
        _ => false,
    }
}

/// Hash algorithms `S2612` flags inside `createHash` calls.
pub(crate) const WEAK_HASH_ALGORITHMS: [&str; 2] = ["md5", "sha1"];

/// The wider deprecated-hash family `S4790` flags.
pub(crate) const WEAK_HASH_FAMILY: [&str; 4] = ["md2", "md4", "md5", "sha1"];

/// Encryption APIs whose mere use `S4787` asks a developer to review.
pub(crate) const ENCRYPT_API_NAMES: [&str; 6] = [
    "createCipheriv",
    "createDecipheriv",
    "publicEncrypt",
    "privateDecrypt",
    "generateKeyPair",
    "generateKeyPairSync",
];

/// TLS protocol versions `S4423` flags in string literals.
pub(crate) const WEAK_TLS_PROTOCOLS: [&str; 4] = ["sslv2", "sslv3", "tlsv1", "tlsv1.0"];

/// Elliptic curves `S4426` considers too weak for key generation.
pub(crate) const WEAK_EC_CURVES: [&str; 8] = [
    "secp112r1",
    "secp128r1",
    "secp160r1",
    "secp192r1",
    "prime192v1",
    "prime192v2",
    "prime192v3",
    "sect163r1",
];

/// Cipher families `S5547` considers broken.
pub(crate) const WEAK_CIPHER_FAMILIES: [&str; 6] = ["des", "rc2", "rc4", "bf", "blowfish", "idea"];

/// Shell-interpreter child-process sinks `S4721` flags.
pub(crate) const SHELL_EXEC_NAMES: [&str; 2] = ["exec", "execSync"];

/// Process-launching APIs whose bare executable name `S4036` flags.
pub(crate) const PATH_LOOKUP_APIS: [&str; 6] = [
    "exec",
    "execSync",
    "execFile",
    "execFileSync",
    "spawn",
    "spawnSync",
];

/// JWT algorithms `S5659` rejects for signing and verification.
pub(crate) const WEAK_JWT_ALGORITHMS: [&str; 1] = ["none"];

/// Angular sanitizer bypass methods `S6268` flags.
pub(crate) const ANGULAR_BYPASS_METHODS: [&str; 5] = [
    "bypassSecurityTrustHtml",
    "bypassSecurityTrustStyle",
    "bypassSecurityTrustScript",
    "bypassSecurityTrustUrl",
    "bypassSecurityTrustResourceUrl",
];

/// CSP fetch directives (helmet's camelCase keys) whose disabling `S5728` flags.
pub(crate) const CSP_FETCH_DIRECTIVES: [&str; 10] = [
    "defaultSrc",
    "scriptSrc",
    "styleSrc",
    "imgSrc",
    "connectSrc",
    "fontSrc",
    "objectSrc",
    "mediaSrc",
    "frameSrc",
    "workerSrc",
];

/// Referrer-Policy values `S5736` considers unsafe.
pub(crate) const UNSAFE_REFERRER_POLICIES: [&str; 2] = ["unsafe-url", "no-referrer-when-downgrade"];

/// Archive-extraction entry points `S5042` asks developers to review.
pub(crate) const ARCHIVE_EXTRACT_APIS: [&str; 5] =
    ["unzip", "unzipSync", "untar", "extract", "extractAllTo"];

/// Cleartext transport modules `S5332` flags on import and `require`.
pub(crate) const CLEARTEXT_MODULES: [&str; 2] = ["http", "ws"];

/// Identifier fragments whose presence in logged arguments `S5757` flags.
pub(crate) const SENSITIVE_DATA_FRAGMENTS: [&str; 6] = [
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "api_key",
];

/// First call argument as a string-literal value, if it is one.
pub(crate) fn first_string_argument<'a>(call: &'a CallExpression<'_>) -> Option<&'a str> {
    let argument = call.arguments.first()?;
    match unparenthesized(argument_expression(argument)?) {
        Expression::StringLiteral(literal) => Some(literal.value.as_str()),
        _ => None,
    }
}

/// Value of a static or quoted-string key inside an object literal.
pub(crate) fn object_property<'a, 'b>(
    object: &'a ObjectExpression<'b>,
    key: &str,
) -> Option<&'a Expression<'b>> {
    object.properties.iter().find_map(|property| {
        let ObjectPropertyKind::ObjectProperty(inner) = property else {
            return None;
        };
        match duplicated_key_name(&inner.key) {
            Some(name) if name == key => Some(&inner.value),
            _ => None,
        }
    })
}

/// String value of an object-literal key, if it holds a string literal.
pub(crate) fn string_property<'a>(object: &'a ObjectExpression<'_>, key: &str) -> Option<&'a str> {
    match object_property(object, key)? {
        Expression::StringLiteral(literal) => Some(literal.value.as_str()),
        _ => None,
    }
}

/// Boolean value of an object-literal key, if it holds a boolean literal.
pub(crate) fn boolean_property(object: &ObjectExpression<'_>, key: &str) -> Option<bool> {
    match object_property(object, key)? {
        Expression::BooleanLiteral(literal) => Some(literal.value),
        _ => None,
    }
}

/// String-literal value of the call argument at `index`, if it is one.
pub(crate) fn string_argument_at<'a>(
    call: &'a CallExpression<'_>,
    index: usize,
) -> Option<&'a str> {
    let argument = call.arguments.get(index)?;
    match unparenthesized(argument_expression(argument)?) {
        Expression::StringLiteral(literal) => Some(literal.value.as_str()),
        _ => None,
    }
}

/// Numeric value of an object-literal key, if it holds a numeric literal.
pub(crate) fn number_property(object: &ObjectExpression<'_>, key: &str) -> Option<f64> {
    match object_property(object, key)? {
        Expression::NumericLiteral(literal) => Some(literal.value),
        _ => None,
    }
}

/// Security-hotspot collector: sink tables and option-object inspections.
pub(crate) struct SecurityHotspotCollector<'s, 'index> {
    pub(crate) source: &'s str,
    pub(crate) sink: IssueSink<'index>,
}

/// Modules whose imports `S4818` flags as raw socket surfaces.
pub(crate) const RAW_SOCKET_MODULES: [&str; 2] = ["net", "dgram"];

impl<'a> Visit<'a> for SecurityHotspotCollector<'_, '_> {
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        self.check_hash_sink(it);
        self.check_encrypt_api(it);
        self.check_key_generation(it);
        self.check_cipher_mode(it);
        self.check_weak_cipher(it);
        self.check_shell_exec(it);
        self.check_math_random(it);
        self.check_jwt_algorithms(it);
        self.check_angular_bypass(it);
        self.check_message_handler(it);
        self.check_window_open(it);
        self.check_sensitive_log(it);
        self.check_error_middleware(it);
        self.check_cors_wildcard(it);
        self.check_cleartext_require(it);
        self.check_cookie_options(it);
        self.check_xml_parser(it);
        self.check_upload_limits(it);
        self.check_body_parser_limit(it);
        self.check_helmet_config(it);
        self.check_header_call(it);
        self.check_csrf_disabled(it);
        self.check_archive_extraction(it);
        self.check_xpath_usage(it);
        self.check_socket_require(it);
        self.check_s3_create_bucket(it);
        walk_call_expression(self, it);
    }

    fn visit_string_literal(&mut self, it: &StringLiteral<'a>) {
        self.check_tls_protocol_literal(it);
        self.check_cleartext_scheme(it);
        self.check_vue_v_html_string(&it.value, it.span());
        walk_string_literal(self, it);
    }

    fn visit_member_expression(&mut self, it: &MemberExpression<'a>) {
        self.check_sensitive_permission(it);
        self.check_forwarded_header_trust(it);
        self.check_command_line_arguments(it);
        self.check_standard_input_reads(it);
        walk_member_expression(self, it);
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        self.check_tls_validation_disabled(it);
        walk_assignment_expression(self, it);
    }

    fn visit_import_declaration(&mut self, it: &ImportDeclaration<'a>) {
        self.check_xpath_module_import(it);
        self.check_socket_module_import(it);
        if CLEARTEXT_MODULES.contains(&it.source.value.as_str()) {
            self.sink.emit_span(
                RuleScope::Both,
                "S5332",
                "Use TLS-protected communication instead of this cleartext protocol.",
                it.span(),
            );
        }
        walk_import_declaration(self, it);
    }

    fn visit_object_property(&mut self, it: &ObjectProperty<'a>) {
        self.check_option_property(it);
        walk_object_property(self, it);
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        self.check_new_upload(it);
        self.check_new_xpath_evaluator(it);
        self.check_new_raw_socket(it);
        self.check_new_s3_bucket_command(it);
        walk_new_expression(self, it);
    }

    fn visit_template_literal(&mut self, it: &TemplateLiteral<'a>) {
        self.check_vue_v_html_template(it);
        walk_template_literal(self, it);
    }
}
