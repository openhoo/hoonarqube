// Residual rule machinery for 'expression' (extracted from lib.rs).
use crate::rules::shared::CONSOLE_METHODS;
use crate::rules::shared::argument_expression;
use crate::rules::shared::call_property;
use crate::support::{
    IssueSink, RuleScope, constructor_name, identifier_name, member_object, member_root_name,
    member_rooted_at, unparenthesized,
};
use oxc_ast::AstKind;
use oxc_ast::ast::{
    Argument, ArrayExpressionElement, AssignmentTarget, BindingIdentifier, CallExpression,
    Expression, Function, FunctionType, IdentifierReference, MemberExpression, NewExpression,
    ObjectExpression, ObjectPropertyKind, PropertyKey, PropertyKind, Statement, TSLiteral, TSType,
    TSTypeName, TSTypeOperatorOperator, ThisExpression, UnaryOperator, VariableDeclaration,
    VariableDeclarationKind, VariableDeclarator,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{walk_member_expression, walk_variable_declaration};
use oxc_semantic::{Semantic, SymbolId};
use oxc_span::{GetSpan, Span};
use oxc_syntax::scope::ScopeFlags;
use std::collections::HashSet;

/// `S106`, `S1442`, `S6637`, and `S6676`.
pub(crate) fn check_logging_and_binding_calls(
    sink: &mut IssueSink,
    it: &CallExpression<'_>,
    property: &str,
    member: &MemberExpression<'_>,
) {
    if member_rooted_at(member, "console") && CONSOLE_METHODS.contains(&property) {
        sink.emit_span(
            RuleScope::Both,
            "S106",
            "Unexpected console statement.",
            it.callee.span(),
        );
    }
    if property == "alert" {
        sink.emit_span(
            RuleScope::JsOnly,
            "S1442",
            "Remove this use of \"alert\".",
            it.callee.span(),
        );
    }
    if property == "bind"
        && it.arguments.len() == 1
        && argument_expression(&it.arguments[0]).is_some()
        && bind_target_is_unnecessary(member_object(member))
    {
        let span = match member {
            MemberExpression::StaticMemberExpression(member) => member.property.span(),
            _ => it.callee.span(),
        };
        sink.emit_span(
            RuleScope::Both,
            "S6637",
            "The function binding is unnecessary.",
            span,
        );
    }
    if matches!(property, "call" | "apply") && it.arguments.len() == 1 {
        sink.emit_span(
            RuleScope::Both,
            "S6676",
            "Invoke this function directly instead of via \"call\"/\"apply\".",
            it.callee.span(),
        );
    }
}

/// `S6666`, `S6959`, `S2871`, `S6653`, `S2685`, `S6654`, and `S6661`. The
/// `S6666` proof reports literal array arguments for every receiver, and
/// evidenced nonliteral arguments (including borrowed `Array.prototype.slice`
/// calls and forwarded wrapper parameters) where the spread rewrite preserves
/// the receiver's `this`.
pub(crate) fn check_collection_and_object_calls(
    sink: &mut IssueSink,
    it: &CallExpression<'_>,
    property: &str,
    member: &MemberExpression<'_>,
    semantic: Option<&Semantic<'_>>,
) {
    if property == "apply" && it.arguments.len() == 2 {
        let argument = argument_expression(&it.arguments[1]);
        // A literal array argument carries its array proof in place, so it
        // stays reported for every receiver: the tracked oracle control
        // `h.apply(ctx, [args])` pins exactly this shape as a finding.
        let literal_array =
            argument.is_some_and(|argument| matches!(argument, Expression::ArrayExpression(_)));
        // A nonliteral argument needs same-file array evidence before the
        // call can become `f(...spread)`, and the rewrite must preserve the
        // callee's `this`: only null/undefined/void receivers, or a thisArg
        // that is exactly the object the applied member was read from
        // (`o.m.apply(o, ...)`), qualify. Arbitrary second arguments are
        // never reported merely for sitting in an `apply` call.
        let evidenced_array = !literal_array
            && argument.is_some_and(|argument| {
                semantic.is_some_and(|semantic| established_array_argument(argument, semantic))
            })
            && (this_arg_is_neutral(it) || this_arg_is_applied_member_object(it, member));
        if literal_array {
            sink.emit_span(
                RuleScope::Both,
                "S6666",
                "Use spread syntax instead of \"apply\".",
                it.arguments[1].span(),
            );
        } else if evidenced_array {
            sink.emit_span(
                RuleScope::Both,
                "S6666",
                "Use the spread operator instead of '.apply()'.",
                it.span(),
            );
        }
    }
    if property == "reduce" && it.arguments.len() == 1 {
        sink.emit_span(
            RuleScope::Both,
            "S6959",
            "Provide an initial accumulator value to this \"reduce\".",
            it.callee.span(),
        );
    }
    check_sort_call(sink, it, property, member, semantic);
    if property == "hasOwnProperty" {
        sink.emit_span(
            RuleScope::Both,
            "S6653",
            "Use \"Object.hasOwn()\" instead of \"hasOwnProperty()\".",
            it.callee.span(),
        );
    }
    if matches!(property, "caller" | "callee") && member_root_name(member) == Some("arguments") {
        sink.emit_span(
            RuleScope::Both,
            "S2685",
            "Avoid arguments.callee.",
            it.callee.span(),
        );
    }
    if property == "assign"
        && member_rooted_at(member, "Object")
        && it
            .arguments
            .first()
            .and_then(argument_expression)
            .is_some_and(|argument| matches!(argument, Expression::ObjectExpression(_)))
    {
        sink.emit_span(
            RuleScope::Both,
            "S6661",
            "Use object spread syntax instead of \"Object.assign\".",
            it.arguments[0].span(),
        );
    }
}

/// `S2871`: a comparator-less `sort`/`toSorted` on a receiver that is not
/// provably a string collection. Alphabetical ordering of strings is the
/// documented compliant case, so string-iterable receivers stay silent.
fn check_sort_call(
    sink: &mut IssueSink,
    it: &CallExpression<'_>,
    property: &str,
    member: &MemberExpression<'_>,
    semantic: Option<&Semantic<'_>>,
) {
    if !matches!(property, "sort" | "toSorted")
        || !it.arguments.is_empty()
        || sort_receiver_is_string_iterable(member_object(member), semantic)
    {
        return;
    }
    let span = match member {
        MemberExpression::StaticMemberExpression(member) => member.property.span(),
        _ => it.callee.span(),
    };
    sink.emit_span(
        RuleScope::Both,
        "S2871",
        "Provide a compare function to avoid sorting elements alphabetically.",
        span,
    );
}

/// Whether the `apply` receiver is one a spread rewrite preserves: only
/// `null`, `undefined`, and `void <expression>` leave the callee with the
/// same `this` that `f(...arguments)` provides.
fn this_arg_is_neutral(call: &CallExpression<'_>) -> bool {
    let Some(expression) = call.arguments.first().and_then(argument_expression) else {
        return false;
    };
    let peeled = unparenthesized(expression);
    match peeled {
        Expression::NullLiteral(_) => true,
        Expression::Identifier(_) => identifier_name(peeled) == Some("undefined"),
        Expression::UnaryExpression(unary) => unary.operator == UnaryOperator::Void,
        _ => false,
    }
}

/// Whether the `apply` receiver is exactly the object the applied member was
/// read from, so `o.m.apply(o, arguments)` and `o.m(...arguments)` share the
/// same `this`.
fn this_arg_is_applied_member_object(
    call: &CallExpression<'_>,
    member: &MemberExpression<'_>,
) -> bool {
    let Some(this_arg) = call.arguments.first().and_then(argument_expression) else {
        return false;
    };
    let Some(applied_member) = member_object(member).as_member_expression() else {
        return false;
    };
    let object = unparenthesized(member_object(applied_member));
    let receiver = unparenthesized(this_arg);
    if matches!(
        (object, receiver),
        (Expression::ThisExpression(_), Expression::ThisExpression(_))
    ) {
        return true;
    }
    match (identifier_name(object), identifier_name(receiver)) {
        (Some(object_name), Some(receiver_name)) => object_name == receiver_name,
        _ => false,
    }
}

/// Whether the second `apply` argument is conservatively established to be
/// an array: a same-file binding initialized from an array value, a forwarded
/// wrapper parameter, or a call whose contract returns a fresh array.
fn established_array_argument(argument: &Expression<'_>, semantic: &Semantic<'_>) -> bool {
    match unparenthesized(argument) {
        Expression::Identifier(identifier) => {
            binding_declaration_init(identifier, semantic)
                .is_some_and(|init| array_producing_expression(init, semantic))
                || declared_array_parameter(identifier, semantic)
        }
        Expression::NewExpression(new_expression) => array_producing_new(new_expression),
        Expression::CallExpression(call) => array_producing_call(call, semantic),
        _ => false,
    }
}

/// Whether the expression establishes an array value when it initializes a
/// binding. TypeScript-only wrappers (`as`, `satisfies`, `!`) are peeled.
fn array_producing_expression(expression: &Expression<'_>, semantic: &Semantic<'_>) -> bool {
    match unparenthesized(expression) {
        Expression::ArrayExpression(_) => true,
        Expression::NewExpression(new_expression) => array_producing_new(new_expression),
        Expression::CallExpression(call) => array_producing_call(call, semantic),
        Expression::TSAsExpression(as_expression) => {
            array_producing_expression(&as_expression.expression, semantic)
        }
        Expression::TSSatisfiesExpression(satisfies_expression) => {
            array_producing_expression(&satisfies_expression.expression, semantic)
        }
        Expression::TSNonNullExpression(non_null_expression) => {
            array_producing_expression(&non_null_expression.expression, semantic)
        }
        _ => false,
    }
}

/// `new Array(...)` always produces an array.
fn array_producing_new(new_expression: &NewExpression<'_>) -> bool {
    constructor_name(new_expression) == Some("Array")
}

/// Calls whose documented contract returns a fresh array, including a
/// borrowed `Array.prototype.slice` invoked through `call`.
fn array_producing_call(call: &CallExpression<'_>, semantic: &Semantic<'_>) -> bool {
    let Some((property, member)) = call_property(call) else {
        return false;
    };
    if property == "call" {
        return borrowed_slice_produces_array(member, call, semantic);
    }
    if member_rooted_at(member, "Array") {
        return matches!(property, "from" | "of");
    }
    if member_rooted_at(member, "Object") {
        return matches!(property, "keys" | "values" | "entries");
    }
    matches!(
        property,
        "concat"
            | "slice"
            | "splice"
            | "map"
            | "filter"
            | "flat"
            | "flatMap"
            | "reverse"
            | "sort"
            | "toSorted"
            | "toReversed"
            | "toSpliced"
            | "with"
            | "split"
    )
}

/// Whether the call is a borrowed `Array.prototype.slice` invocation with a
/// proven array-like source: `slice.call(arguments, 1)` always returns a
/// fresh array, while object-like arrays and unknown sources stay unproven.
fn borrowed_slice_produces_array(
    member: &MemberExpression<'_>,
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
) -> bool {
    let slice_callee = unparenthesized(member_object(member));
    let proven_slice = match slice_callee {
        Expression::Identifier(identifier) => binding_declaration_init(identifier, semantic)
            .is_some_and(|init| is_array_prototype_slice_member(init)),
        _ => is_array_prototype_slice_member(slice_callee),
    };
    if !proven_slice {
        return false;
    }
    let Some(source) = call.arguments.first().and_then(argument_expression) else {
        return false;
    };
    array_like_slice_source(source, semantic)
}

/// Whether the expression is the direct `Array.prototype.slice` member read.
fn is_array_prototype_slice_member(expression: &Expression<'_>) -> bool {
    let Some(MemberExpression::StaticMemberExpression(member)) =
        unparenthesized(expression).as_member_expression()
    else {
        return false;
    };
    member.property.name == "slice" && slice_prototype_object_is_array(&member.object)
}

/// Whether the expression reads `Array.prototype` through a static member
/// rooted at the `Array` identifier.
fn slice_prototype_object_is_array(object: &Expression<'_>) -> bool {
    let Some(MemberExpression::StaticMemberExpression(prototype)) =
        unparenthesized(object).as_member_expression()
    else {
        return false;
    };
    prototype.property.name == "prototype" && identifier_name(&prototype.object) == Some("Array")
}

/// Whether the borrowed slice source is one the fresh-array proof covers: the
/// `arguments` object, an array literal, or a conservatively established
/// array. Object-like arrays (`{ 0: "a", length: 1 }`) and unknown receivers
/// stay unproven.
fn array_like_slice_source(expression: &Expression<'_>, semantic: &Semantic<'_>) -> bool {
    let peeled = unparenthesized(expression);
    if identifier_name(peeled) == Some("arguments") {
        return true;
    }
    matches!(peeled, Expression::ArrayExpression(_))
        || established_array_argument(expression, semantic)
}

fn binding_declaration_init<'a>(
    identifier: &IdentifierReference<'_>,
    semantic: &Semantic<'a>,
) -> Option<&'a Expression<'a>> {
    binding_declarator(identifier, semantic).and_then(|declarator| declarator.init.as_ref())
}

/// Whether the comparator-less `sort`/`toSorted` receiver is conservatively
/// a string iterable, where alphabetical ordering is the documented
/// compliant case for `S2871`: a string-literal array, a binding declared
/// or initialized as a string collection, or a call/constructor whose
/// result is provably `string[]`/`Set<string>`.
fn sort_receiver_is_string_iterable(
    expression: &Expression<'_>,
    semantic: Option<&Semantic<'_>>,
) -> bool {
    match unparenthesized(expression) {
        Expression::ArrayExpression(array) => array_elements_all_strings(array, semantic),
        Expression::Identifier(identifier) => semantic
            .and_then(|semantic| binding_declarator(identifier, semantic))
            .is_some_and(|declarator| {
                declarator
                    .type_annotation
                    .as_ref()
                    .is_some_and(|annotation| type_is_string_iterable(&annotation.type_annotation))
                    || declarator
                        .init
                        .as_ref()
                        .is_some_and(|init| sort_receiver_is_string_iterable(init, semantic))
            }),
        Expression::CallExpression(call) => string_iterable_call(call, semantic),
        Expression::NewExpression(new_expression) => string_iterable_new(new_expression, semantic),
        Expression::TSAsExpression(as_expression) => {
            type_is_string_iterable(&as_expression.type_annotation)
        }
        Expression::TSSatisfiesExpression(satisfies) => {
            type_is_string_iterable(&satisfies.type_annotation)
                || sort_receiver_is_string_iterable(&satisfies.expression, semantic)
        }
        Expression::TSNonNullExpression(non_null) => {
            sort_receiver_is_string_iterable(&non_null.expression, semantic)
        }
        _ => false,
    }
}

/// Whether every element of an array literal is statically a string
/// (string literals, static templates, or spreads of string iterables).
/// An empty literal proves nothing and stays reported.
fn array_elements_all_strings(
    array: &oxc_ast::ast::ArrayExpression<'_>,
    semantic: Option<&Semantic<'_>>,
) -> bool {
    !array.elements.is_empty()
        && array.elements.iter().all(|element| match element {
            ArrayExpressionElement::SpreadElement(spread) => {
                sort_receiver_is_string_iterable(&spread.argument, semantic)
            }
            _ => element
                .as_expression()
                .is_some_and(is_static_string_expression),
        })
}

/// Whether the expression is statically a string value: a string literal
/// or a template literal without substitutions, behind TypeScript-only
/// wrappers.
fn is_static_string_expression(expression: &Expression<'_>) -> bool {
    match expression {
        Expression::StringLiteral(_) => true,
        Expression::TemplateLiteral(template) => template.expressions.is_empty(),
        Expression::TSAsExpression(as_expression) => {
            is_static_string_expression(&as_expression.expression)
        }
        Expression::TSSatisfiesExpression(satisfies) => {
            is_static_string_expression(&satisfies.expression)
        }
        Expression::TSNonNullExpression(non_null) => {
            is_static_string_expression(&non_null.expression)
        }
        _ => false,
    }
}

/// Whether a `new` expression provably produces a string collection:
/// `new Array<string>`/`new Set<string>` by type argument, or
/// `new Array`/`new Set`/`Array.from` shapes whose arguments are all
/// statically strings.
fn string_iterable_new(
    new_expression: &NewExpression<'_>,
    semantic: Option<&Semantic<'_>>,
) -> bool {
    let Some(name) = constructor_name(new_expression) else {
        return false;
    };
    if !matches!(name, "Array" | "Set") {
        return false;
    }
    if let Some(type_arguments) = &new_expression.type_arguments {
        return type_arguments.params.first().is_some_and(type_is_string);
    }
    !new_expression.arguments.is_empty()
        && new_expression
            .arguments
            .iter()
            .all(|argument| match argument {
                Argument::SpreadElement(spread) => {
                    sort_receiver_is_string_iterable(&spread.argument, semantic)
                }
                _ => argument.as_expression().is_some_and(|expression| {
                    is_static_string_expression(unparenthesized(expression))
                }),
            })
}

/// Whether a call provably produces a string array: `Object.keys`,
/// `Object.getOwnPropertyNames`, `String` mapping, `split`/`match` on a
/// string receiver, `Array.from`/`Array.of` over strings, or an
/// element-preserving array method on a string-iterable receiver.
fn string_iterable_call(call: &CallExpression<'_>, semantic: Option<&Semantic<'_>>) -> bool {
    let Some((property, member)) = call_property(call) else {
        return false;
    };
    if member_rooted_at(member, "Object") {
        return matches!(property, "keys" | "getOwnPropertyNames");
    }
    if member_rooted_at(member, "Array") {
        return match property {
            "from" => call
                .arguments
                .first()
                .and_then(argument_expression)
                .is_some_and(|argument| sort_receiver_is_string_iterable(argument, semantic)),
            "of" => {
                !call.arguments.is_empty()
                    && call.arguments.iter().all(|argument| {
                        argument.as_expression().is_some_and(|expression| {
                            is_static_string_expression(unparenthesized(expression))
                        })
                    })
            }
            _ => false,
        };
    }
    match property {
        "split" | "match" => true,
        "map" => call
            .arguments
            .first()
            .and_then(argument_expression)
            .is_some_and(|argument| identifier_name(unparenthesized(argument)) == Some("String")),
        "concat" => {
            sort_receiver_is_string_iterable(member_object(member), semantic)
                && !call.arguments.is_empty()
                && call.arguments.iter().all(|argument| {
                    argument.as_expression().is_some_and(|expression| {
                        is_static_string_expression(unparenthesized(expression))
                            || sort_receiver_is_string_iterable(expression, semantic)
                    })
                })
        }
        "slice" | "splice" | "filter" | "flat" | "reverse" | "sort" | "toSorted" | "toReversed"
        | "toSpliced" | "with" => sort_receiver_is_string_iterable(member_object(member), semantic),
        _ => false,
    }
}

/// Whether the type annotation describes a string-element collection:
/// `string[]`, `readonly string[]`, `Array<string>`,
/// `ReadonlyArray<string>`, `Set<string>`, `ReadonlySet<string>`, or
/// `Iterable<string>`.
fn type_is_string_iterable(ty: &TSType<'_>) -> bool {
    match ty {
        TSType::TSArrayType(array) => type_is_string(&array.element_type),
        TSType::TSTypeReference(reference) => {
            let Some(name) = type_reference_name(&reference.type_name) else {
                return false;
            };
            matches!(
                name,
                "Array" | "ReadonlyArray" | "Set" | "ReadonlySet" | "Iterable"
            ) && reference
                .type_arguments
                .as_ref()
                .and_then(|arguments| arguments.params.first())
                .is_some_and(type_is_string)
        }
        TSType::TSParenthesizedType(parenthesized) => {
            type_is_string_iterable(&parenthesized.type_annotation)
        }
        TSType::TSTypeOperatorType(operator) => {
            operator.operator == TSTypeOperatorOperator::Readonly
                && type_is_string_iterable(&operator.type_annotation)
        }
        _ => false,
    }
}

/// Whether the type is statically `string`: the `string` keyword or a
/// union/literal composed only of string types.
fn type_is_string(ty: &TSType<'_>) -> bool {
    match ty {
        TSType::TSStringKeyword(_) => true,
        TSType::TSLiteralType(literal) => matches!(
            &literal.literal,
            TSLiteral::StringLiteral(_) | TSLiteral::TemplateLiteral(_)
        ),
        TSType::TSUnionType(union) => union.types.iter().all(type_is_string),
        TSType::TSParenthesizedType(parenthesized) => {
            type_is_string(&parenthesized.type_annotation)
        }
        _ => false,
    }
}

/// Plain identifier name of a type reference (`Array` in `Array<string>`).
fn type_reference_name<'a>(name: &'a TSTypeName<'a>) -> Option<&'a str> {
    match name {
        TSTypeName::IdentifierReference(identifier) => Some(identifier.name.as_str()),
        _ => None,
    }
}

/// The variable declarator an identifier resolves to, when that binding is
/// a variable that is never reassigned.
fn binding_declarator<'a>(
    identifier: &IdentifierReference<'_>,
    semantic: &Semantic<'a>,
) -> Option<&'a VariableDeclarator<'a>> {
    let reference_id = identifier.reference_id.get()?;
    let symbol_id = semantic.scoping().get_reference(reference_id).symbol_id()?;
    if semantic.nodes().is_empty() || semantic.scoping().symbol_is_mutated(symbol_id) {
        return None;
    }
    let AstKind::VariableDeclarator(declarator) = semantic.symbol_declaration(symbol_id).kind()
    else {
        return None;
    };
    Some(declarator)
}

/// Whether the identifier resolves to the unmutated parameter of a returned
/// function-expression wrapper that forwards it as an `apply` argument. The
/// wrapper shape establishes the variadic array contract without relying on
/// a parameter name; arbitrary formal parameters remain unproven.
fn declared_array_parameter(identifier: &IdentifierReference<'_>, semantic: &Semantic<'_>) -> bool {
    if semantic.nodes().is_empty() {
        return false;
    }
    let Some(reference_id) = identifier.reference_id.get() else {
        return false;
    };
    let Some(symbol_id) = semantic.scoping().get_reference(reference_id).symbol_id() else {
        return false;
    };
    if semantic.scoping().symbol_is_mutated(symbol_id) {
        return false;
    }
    let declaration = semantic.symbol_declaration(symbol_id);
    if !matches!(declaration.kind(), AstKind::FormalParameter(_)) {
        return false;
    }
    let Some(function) = semantic
        .nodes()
        .ancestors(declaration.id())
        .find_map(|node| match node.kind() {
            AstKind::Function(function) => Some(function),
            _ => None,
        })
    else {
        return false;
    };
    if !matches!(function.r#type, FunctionType::FunctionExpression)
        || function.params.items.len() != 1
        || function.params.rest.is_some()
        || !matches!(
            semantic.nodes().parent_kind(function.node_id.get()),
            AstKind::ReturnStatement(_)
        )
    {
        return false;
    }
    let Some(body) = function.body.as_deref() else {
        return false;
    };
    let [Statement::ReturnStatement(return_statement)] = body.statements.as_slice() else {
        return false;
    };
    let Some(Expression::CallExpression(call)) =
        return_statement.argument.as_ref().map(unparenthesized)
    else {
        return false;
    };
    let Some((property, _)) = call_property(call) else {
        return false;
    };
    if property != "apply" || call.arguments.len() != 2 {
        return false;
    }
    let Some(Expression::Identifier(forwarded)) =
        call.arguments[1].as_expression().map(unparenthesized)
    else {
        return false;
    };
    forwarded
        .reference_id
        .get()
        .and_then(|reference_id| semantic.scoping().get_reference(reference_id).symbol_id())
        == Some(symbol_id)
}

/// Whether the `.bind(...)` receiver is a function whose own `this` is not
/// needed. Arrow functions never own `this`; ordinary functions do unless
/// their body (excluding nested ordinary functions) uses it.
fn bind_target_is_unnecessary(expression: &Expression<'_>) -> bool {
    match unparenthesized(expression) {
        Expression::ArrowFunctionExpression(_) => true,
        Expression::FunctionExpression(function) => !function_uses_this(function),
        _ => false,
    }
}

fn function_uses_this(function: &Function<'_>) -> bool {
    let mut collector = ThisUsageCollector::default();
    collector.visit_formal_parameters(&function.params);
    if let Some(body) = function.body.as_deref() {
        collector.visit_function_body(body);
    }
    collector.found_this
}

#[derive(Default)]
struct ThisUsageCollector {
    found_this: bool,
}

impl<'a> Visit<'a> for ThisUsageCollector {
    fn visit_this_expression(&mut self, _: &ThisExpression) {
        self.found_this = true;
    }

    // A nested ordinary function has its own `this`, so it must not make the
    // enclosing function appear to use its receiver.
    fn visit_function(&mut self, _: &Function<'a>, _: ScopeFlags) {}
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6637_flags_arrow_and_plain_functions_without_this() {
        let findings = js_keys(
            "const arrow = (() => 1).bind(receiver);\n\
             const plain = function () {}.bind(receiver);\n",
        );
        assert_eq!(count_key(&findings, "javascript:S6637"), 2);
    }

    #[test]
    fn s6637_preserves_outer_this_and_meaningful_arguments() {
        let findings = js_keys(
            "const uses = function () { return this.value; }.bind(receiver);\n\
             const nested_arrow = function () { return () => this.value; }.bind(receiver);\n\
             const nested_function = function () { return function () { return this.value; }; }.bind(receiver);\n\
             const extra_args = function () {}.bind(receiver, value);\n\
             const spread = function () {}.bind(...values);\n",
        );
        // The nested ordinary function owns its own `this`; only the outer
        // binding is unnecessary in that case.
        assert_eq!(count_key(&findings, "javascript:S6637"), 1);
    }

    #[test]
    fn s6637_keeps_the_legacy_good_fixture_as_positive_evidence() {
        let findings = js_keys("const f = function () {}.bind(this);\n");
        assert_eq!(count_key(&findings, "javascript:S6637"), 1);
    }

    #[test]
    fn s6666_reports_pinned_express_nonliteral_apply_sites() {
        // #252: verbatim expressjs/express@53d4a0d606c0388f764f192b306ce0e90200e7e8
        // lib/application.js (MIT). SonarQube 26.8.0.126808 (Sonar way)
        // reports exactly these three S6666 sites: the array-producing
        // `slice.call(...)` argument and the array-valued `args` identifiers.
        let report = js(include_str!(
            "../../../fixtures/shapes/express-application.js"
        ));
        let sites: Vec<((u32, u32), (u32, u32))> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S6666")
            .map(|issue| {
                (
                    (issue.range.start.line, issue.range.start.column),
                    (issue.range.end.line, issue.range.end.column),
                )
            })
            .collect();
        assert_eq!(
            sites,
            vec![
                ((479, 4), (479, 56)),
                ((499, 4), (499, 40)),
                ((605, 9), (605, 42)),
            ]
        );
    }

    #[test]
    fn s6666_reports_pinned_axios_spread_site() {
        // #252: verbatim axios/axios@18e7dfedf30c96e58652887f930642ae82e0130c
        // lib/helpers/spread.js (MIT). SonarQube 26.8.0.126808 (Sonar way)
        // reports the `callback.apply(null, arr)` wrapper call at line 26.
        let report = js(include_str!("../../../fixtures/shapes/axios-spread.js"));
        let sites: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S6666")
            .map(|issue| {
                (
                    (issue.range.start.line, issue.range.start.column),
                    (issue.range.end.line, issue.range.end.column),
                    issue.message.as_str(),
                )
            })
            .collect();
        assert_eq!(
            sites,
            vec![(
                (26, 11),
                (26, 36),
                "Use the spread operator instead of '.apply()'."
            )]
        );
    }

    #[test]
    fn s6666_reports_spread_safe_nonliteral_array_arguments() {
        let findings = js_keys(
            "const args = [1, 2];\n\
             const values = list.map(toValue);\n\
             const slice = Array.prototype.slice;\n\
             fn.apply(null, args);\n\
             fn.apply(undefined, args);\n\
             obj.method.apply(obj, values);\n\
             obj.method.apply(obj, slice.call(arguments, 1));\n\
             fn.apply(null, [1, 2]);\n",
        );
        assert_eq!(count_key(&findings, "javascript:S6666"), 5);
    }

    #[test]
    fn s6666_spread_unsafe_and_unrelated_calls_stay_clean() {
        let findings = js_keys(
            "h.apply(ctx, args);\n\
             obj.method.apply(other, args);\n\
             h.apply(args);\n\
             h.call(null, args);\n\
             Reflect.apply(h, this, args);\n\
             h(...args);\n",
        );
        assert_eq!(count_key(&findings, "javascript:S6666"), 0);
    }

    #[test]
    fn s2871_allows_string_collection_sorts() {
        // Alphabetical ordering of provably string collections is the
        // documented compliant case.
        let findings = ts_keys(
            "const typeImports = new Set<string>([\"B\", \"A\"]);\n\
             const sorted = [...typeImports].sort();\n\
             const problems: string[] = [];\n\
             problems.sort();\n\
             const names = [\"b\", \"a\"];\n\
             names.sort();\n\
             Object.keys(record).sort();\n\
             \"a,b\".split(\",\").sort();\n\
             const frozen: readonly string[] = [];\n\
             frozen.toSorted();\n",
        );
        assert_eq!(count_key(&findings, "typescript:S2871"), 0);
    }

    #[test]
    fn s2871_still_flags_non_string_and_unknown_sorts() {
        let findings = ts_keys(
            "const numbers: number[] = [2, 1];\n\
             numbers.sort();\n\
             const mixed = [1, \"a\"];\n\
             mixed.sort();\n\
             const untyped = build();\n\
             untyped.sort();\n",
        );
        assert_eq!(count_key(&findings, "typescript:S2871"), 3);
    }

    #[test]
    fn s2871_allows_string_sorts_without_semantic() {
        // Syntactic string proofs work even where semantic resolution is
        // unavailable (plain JS has no type annotations).
        let findings = js_keys(
            "const names = [\"b\", \"a\"];\n\
             names.sort();\n\
             Object.keys(record).sort();\n\
             items.map(String).sort();\n",
        );
        assert_eq!(count_key(&findings, "javascript:S2871"), 0);
    }
}

/// `S6654` for one member use: reads, call callees, and write targets of
/// the deprecated `__proto__` prototype accessor report at the property
/// span. A receiver that resolves to a const object literal declaring an
/// own `__proto__` member stays silent — that spelling is an ordinary own
/// property, not the inherited accessor.
pub(crate) fn check_proto_member_use(
    sink: &mut IssueSink,
    member: &MemberExpression<'_>,
    own_proto_bindings: &HashSet<SymbolId>,
    semantic: Option<&Semantic<'_>>,
) {
    let Some((receiver, span)) = proto_accessor_member(member) else {
        return;
    };
    emit_proto_member_use(sink, receiver, span, own_proto_bindings, semantic);
}

/// The write-target form of [`proto_accessor_member`]: assignment LHS
/// members live in the separate `AssignmentTarget` enum.
pub(crate) fn proto_write_target<'a, 'b>(
    target: &'a AssignmentTarget<'b>,
) -> Option<(&'a Expression<'b>, Span)> {
    match target {
        AssignmentTarget::StaticMemberExpression(member) if member.property.name == "__proto__" => {
            Some((&member.object, member.property.span))
        }
        AssignmentTarget::ComputedMemberExpression(member) => match &member.expression {
            Expression::StringLiteral(literal) if literal.value == "__proto__" => {
                Some((&member.object, literal.span))
            }
            _ => None,
        },
        _ => None,
    }
}

/// Emits the `S6654` finding when the receiver does not provably own the
/// member.
pub(crate) fn emit_proto_member_use(
    sink: &mut IssueSink,
    receiver: &Expression<'_>,
    span: Span,
    own_proto_bindings: &HashSet<SymbolId>,
    semantic: Option<&Semantic<'_>>,
) {
    if receiver_is_own_proto_binding(receiver, own_proto_bindings, semantic) {
        return;
    }
    sink.emit_span(
        RuleScope::Both,
        "S6654",
        "Use \"Object.getPrototypeOf()\"/\"Object.setPrototypeOf()\" instead of \"__proto__\".",
        span,
    );
}

/// The receiver and property span when `member` names the deprecated
/// accessor — statically or through a literal computed key.
fn proto_accessor_member<'a, 'b>(
    member: &'a MemberExpression<'b>,
) -> Option<(&'a Expression<'b>, Span)> {
    match member {
        MemberExpression::StaticMemberExpression(member) => {
            (member.property.name == "__proto__").then_some((&member.object, member.property.span))
        }
        MemberExpression::ComputedMemberExpression(member) => match &member.expression {
            Expression::StringLiteral(literal) if literal.value == "__proto__" => {
                Some((&member.object, literal.span))
            }
            _ => None,
        },
        MemberExpression::PrivateFieldExpression(_) => None,
    }
}

/// Whether the receiver resolves to a const object literal declaring an
/// own `__proto__` member.
fn receiver_is_own_proto_binding(
    receiver: &Expression<'_>,
    own_proto_bindings: &HashSet<SymbolId>,
    semantic: Option<&Semantic<'_>>,
) -> bool {
    let Expression::Identifier(reference) = unparenthesized(receiver) else {
        return false;
    };
    semantic.is_some_and(|semantic| {
        semantic
            .scoping()
            .get_reference(reference.reference_id())
            .symbol_id()
            .is_some_and(|symbol| own_proto_bindings.contains(&symbol))
    })
}

/// Const bindings whose initializer is an object literal declaring an own
/// `__proto__` member. Symbol-keyed resolution keeps shadowed names out of
/// the suppression set.
pub(crate) fn collect_own_proto_bindings(program: &oxc_ast::ast::Program<'_>) -> HashSet<SymbolId> {
    let mut collector = OwnProtoBindingCollector {
        bindings: HashSet::new(),
    };
    collector.visit_program(program);
    collector.bindings
}

struct OwnProtoBindingCollector {
    bindings: HashSet<SymbolId>,
}

impl<'a> Visit<'a> for OwnProtoBindingCollector {
    fn visit_variable_declaration(&mut self, it: &VariableDeclaration<'a>) {
        // Only `const` bindings keep their initializer's identity; a
        // rebindable `let`/`var` receiver would be a guess.
        if it.kind == VariableDeclarationKind::Const {
            for declarator in &it.declarations {
                self.collect_declarator(declarator);
            }
        }
        walk_variable_declaration(self, it);
    }
}

impl OwnProtoBindingCollector {
    fn collect_declarator(&mut self, declarator: &VariableDeclarator<'_>) {
        let Some(init) = declarator.init.as_ref() else {
            return;
        };
        let Expression::ObjectExpression(object) = unparenthesized(init) else {
            return;
        };
        if !object_has_own_proto_member(object) {
            return;
        }
        if let Some(symbol) = declarator
            .id
            .get_binding_identifier()
            .map(BindingIdentifier::symbol_id)
        {
            self.bindings.insert(symbol);
        }
    }
}

/// Whether the literal declares an own `__proto__` member. Methods,
/// accessors, shorthand, and computed keys always create own members; the
/// plain colon form (`{ __proto__: value }`, string-keyed included) is the
/// prototype setter itself, so it stays reported.
fn object_has_own_proto_member(object: &ObjectExpression<'_>) -> bool {
    object.properties.iter().any(|property| match property {
        ObjectPropertyKind::ObjectProperty(property) => {
            let computed_proto_key = property.computed
                && matches!(&property.key, PropertyKey::StringLiteral(literal) if literal.value == "__proto__");
            if computed_proto_key {
                return true;
            }
            let static_proto_key = match &property.key {
                PropertyKey::StaticIdentifier(identifier) => identifier.name == "__proto__",
                PropertyKey::StringLiteral(literal) => {
                    !property.computed && literal.value == "__proto__"
                }
                _ => false,
            };
            static_proto_key
                && (property.method || property.kind != PropertyKind::Init || property.shorthand)
        }
        ObjectPropertyKind::SpreadProperty(_) => false,
    })
}

/// Whether the `if` test conditions on `Object.setPrototypeOf`
/// availability. The guarded `__proto__` write inside is deliberate
/// compatibility code for engines without the modern API, so it is not a
/// replacement candidate.
pub(crate) fn test_references_set_prototype_of(test: &Expression<'_>) -> bool {
    let mut detector = SetPrototypeOfDetector::default();
    detector.visit_expression(test);
    detector.found
}

#[derive(Default)]
struct SetPrototypeOfDetector {
    found: bool,
}

impl<'a> Visit<'a> for SetPrototypeOfDetector {
    fn visit_member_expression(&mut self, it: &MemberExpression<'a>) {
        if let MemberExpression::StaticMemberExpression(member) = it
            && member.property.name == "setPrototypeOf"
            && matches!(&member.object, Expression::Identifier(object) if object.name == "Object")
        {
            self.found = true;
        }
        walk_member_expression(self, it);
    }
}
