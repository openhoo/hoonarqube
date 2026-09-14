// Rule module s7770_native_coercion_functions (generated).
//
// `javascript:S7770` + `typescript:S7770` — Wrapper functions around
// built-in type conversion functions should be avoided. Reference
// semantics: eslint-plugin-unicorn `prefer-native-coercion-functions` at
// the version pinned by SonarJS 13.x (v65.0.1, wrapped by SonarJS S7770):
//
// - an identity callback `v => v` / `v => { return v; }` passed as the
//   first argument of `every`, `filter`, `find`, `findLast`, `findIndex`,
//   or `findLastIndex` (non-optional, non-computed member call) is
//   equivalent to `Boolean` — TS type-predicate callbacks stay silent;
// - a single-parameter non-async, non-generator function whose body is
//   exactly `BuiltIn(v)` / `{ return BuiltIn(v); }` with `BuiltIn` one of
//   `String`, `Number`, `BigInt`, `Boolean`, or `Symbol` wraps the native
//   conversion. Constructors (`constructor`) and setters stay silent.
//
// The report is anchored on the function head — for arrows the `=>` token,
// otherwise the function start through the parameter-list opening paren —
// with the reference message
// "{functionNameWithKind} is equivalent to `{BuiltIn}`. Use `{BuiltIn}`
// directly." (for example the pinned zod `arrow function is equivalent to
// `Boolean`. Use `Boolean` directly.`). Per the issue guard the built-in is
// only suggested when it is not shadowed: the wrapper callee must resolve
// to a global, and the array-callback replacement requires no `Boolean`
// binding between the callback and the global scope. No auto-fix is
// offered.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{
    BindingIdentifier, BindingPattern, Expression, FunctionBody, MethodDefinitionKind, PropertyKey,
    PropertyKind, TSType, TSTypeAnnotation,
};
use oxc_parser::{Kind, Token};
use oxc_semantic::{AstNode, Semantic};
use oxc_span::{GetSpan, Span};

const ARRAY_METHODS_WITH_BOOLEAN_CALLBACK: [&str; 7] = [
    "every",
    "filter",
    "find",
    "findLast",
    "findIndex",
    "findLastIndex",
    "some",
];

const NATIVE_COERCION_FUNCTIONS: [&str; 5] = ["String", "Number", "BigInt", "Boolean", "Symbol"];

/// Entry point: `javascript:S7770` + `typescript:S7770`
/// prefer-native-coercion-functions check over the parsed program.
/// Requires the semantic model for the shadowing guard, so
/// recoverable-parse files stay silent.
pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut sink = IssueSink {
        index: ctx.index,
        language: ctx.language,
        issues: Vec::new(),
    };
    let Some(semantic) = ctx.semantic else {
        return sink.issues;
    };
    for node in semantic.nodes().iter() {
        match node.kind() {
            AstKind::ArrowFunctionExpression(arrow) => {
                if arrow.r#async {
                    continue;
                }
                let body_expression = arrow.body.as_expression();
                let returned = match &arrow.body {
                    oxc_ast::ast::ArrowFunctionBody::FunctionBody(body) => {
                        single_return_expression(body)
                    }
                    _ => None,
                };
                let head = arrow_token_span(ctx.tokens, arrow.body.span().start);
                check_function(
                    &mut sink,
                    ctx,
                    semantic,
                    node,
                    &FunctionShape {
                        parameters: &arrow.params,
                        return_type: arrow.return_type.as_deref(),
                        function_id: None,
                        body_expression,
                        returned,
                        span: arrow.span(),
                        arrow: true,
                        body_start: Some(arrow.body.span().start),
                    },
                    head,
                );
            }
            AstKind::Function(function) => {
                if function.r#async || function.generator {
                    continue;
                }
                let Some(body) = function.body.as_deref() else {
                    continue;
                };
                check_function(
                    &mut sink,
                    ctx,
                    semantic,
                    node,
                    &FunctionShape {
                        parameters: &function.params,
                        return_type: function.return_type.as_deref(),
                        function_id: function.id.as_ref(),
                        body_expression: None,
                        returned: single_return_expression(body),
                        span: function.span(),
                        arrow: false,
                        body_start: None,
                    },
                    None,
                );
            }
            _ => {}
        }
    }
    sink.issues
}

/// The expression of a single-statement `return` body.
fn single_return_expression<'a>(body: &'a FunctionBody<'a>) -> Option<&'a Expression<'a>> {
    if body.statements.len() != 1 {
        return None;
    }
    match &body.statements[0] {
        oxc_ast::ast::Statement::ReturnStatement(statement) => statement.argument.as_ref(),
        _ => None,
    }
}

/// The reference-shaped parts of one arrow or function node.
struct FunctionShape<'a, 'b> {
    parameters: &'a oxc_ast::ast::FormalParameters<'b>,
    return_type: Option<&'a TSTypeAnnotation<'b>>,
    function_id: Option<&'a BindingIdentifier<'b>>,
    body_expression: Option<&'a Expression<'b>>,
    returned: Option<&'a Expression<'b>>,
    span: Span,
    arrow: bool,
    body_start: Option<u32>,
}

fn check_function<'b>(
    sink: &mut IssueSink<'_>,
    ctx: &AnalysisContext,
    semantic: &Semantic<'b>,
    node: &AstNode<'b>,
    shape: &FunctionShape<'_, 'b>,
    arrow_head: Option<Span>,
) {
    let Some(BindingPattern::BindingIdentifier(parameter)) =
        shape.parameters.items.first().map(|item| &item.pattern)
    else {
        return;
    };
    // The reference constructor/setter guard.
    if is_constructor_or_setter(semantic, node, shape.span) {
        return;
    }
    // The reference `getArrayCallbackProblem`: an identity callback in the
    // first argument of the boolean array methods; TS type-predicate
    // callbacks are excluded.
    let identity = shape
        .body_expression
        .or(shape.returned)
        .is_some_and(|expression| {
            matches!(unparenthesized(expression), Expression::Identifier(identity) if identity.name == parameter.name.as_str())
        });
    let mut replacement = None;
    if identity && !is_type_predicate(shape.return_type) {
        replacement = array_callback_replacement(semantic, node, shape);
    }
    // The reference `getCoercionFunctionProblem`: a wrapper returning
    // `BuiltIn(parameter)`.
    if replacement.is_none()
        && let Some(expression) = shape.body_expression.or(shape.returned)
    {
        replacement = coercion_wrapper_replacement(semantic, expression, parameter);
    }
    let Some(replacement) = replacement else {
        return;
    };
    let name = function_name_with_kind(semantic, node, shape.span, shape.function_id, shape.arrow);
    let head = arrow_head
        .or_else(|| arrow_token_span(ctx.tokens, shape.body_start?))
        .unwrap_or_else(|| {
            function_head_span(semantic, node, shape.parameters, ctx.tokens, shape.span)
        });
    sink.emit_span(
        RuleScope::Both,
        "S7770",
        &format!("{name} is equivalent to `{replacement}`. Use `{replacement}` directly."),
        head,
    );
}

/// The reference constructor/setter guard: functions in `constructor` or
/// setter positions stay silent.
fn is_constructor_or_setter(
    semantic: &Semantic<'_>,
    node: &AstNode<'_>,
    function_span: Span,
) -> bool {
    match semantic.nodes().parent_node(node.id()).kind() {
        AstKind::MethodDefinition(definition)
            if definition.value.span() == function_span
                && matches!(
                    definition.kind,
                    MethodDefinitionKind::Constructor | MethodDefinitionKind::Set
                ) =>
        {
            true
        }
        AstKind::ObjectProperty(property)
            if property.value.span() == function_span && property.kind == PropertyKind::Set =>
        {
            true
        }
        _ => false,
    }
}

/// The `Boolean` replacement when the function is an identity callback in
/// the first argument of a boolean array method, provided `Boolean` is not
/// shadowed between the callback and the global scope.
fn array_callback_replacement<'b>(
    semantic: &Semantic<'b>,
    node: &AstNode<'b>,
    shape: &FunctionShape<'_, 'b>,
) -> Option<&'static str> {
    let parent = significant_parent(semantic, node)?;
    let AstKind::CallExpression(call) = parent.kind() else {
        return None;
    };
    if call.optional || call.arguments.is_empty() || call.arguments[0].span() != shape.span {
        return None;
    }
    let Expression::StaticMemberExpression(member) = unparenthesized(&call.callee) else {
        return None;
    };
    if member.optional
        || !ARRAY_METHODS_WITH_BOOLEAN_CALLBACK.contains(&member.property.name.as_str())
    {
        return None;
    }
    // Issue guard: the suggested built-in must not be shadowed between the
    // callback and the global scope.
    if semantic
        .scoping()
        .find_binding(node.scope_id(), "Boolean".into())
        .is_some()
    {
        return None;
    }
    Some("Boolean")
}

/// The built-in name when the expression is `BuiltIn(parameter)` with the
/// callee resolving to the global built-in (issue shadowing guard).
fn coercion_wrapper_replacement<'b>(
    semantic: &Semantic<'b>,
    expression: &Expression<'b>,
    parameter: &BindingIdentifier<'b>,
) -> Option<&'static str> {
    let Expression::CallExpression(call) = unparenthesized(expression) else {
        return None;
    };
    if call.optional || call.arguments.is_empty() {
        return None;
    }
    let parameter_call = match call.arguments[0].as_expression() {
        Some(Expression::Identifier(first)) => first.name == parameter.name.as_str(),
        _ => false,
    };
    if !parameter_call {
        return None;
    }
    let Expression::Identifier(callee) = unparenthesized(&call.callee) else {
        return None;
    };
    let name = NATIVE_COERCION_FUNCTIONS
        .iter()
        .find(|candidate| **candidate == callee.name.as_str())?;
    // Issue guard: the callee has to resolve to the global built-in, not to
    // a shadowing binding.
    if semantic.is_reference_to_global_variable(callee) {
        Some(name)
    } else {
        None
    }
}

/// The nearest ancestor that is not a parenthesized expression.
fn significant_parent<'a, 'b>(
    semantic: &'a Semantic<'b>,
    node: &AstNode<'b>,
) -> Option<&'a AstNode<'b>> {
    let mut current = semantic.nodes().parent_node(node.id());
    while let AstKind::ParenthesizedExpression(_) = current.kind() {
        let parent = semantic.nodes().parent_node(current.id());
        if parent.id() == current.id() {
            return None;
        }
        current = parent;
    }
    Some(current)
}

/// The reference `getFunctionHeadLocation`: the arrow token for arrows,
/// otherwise the function start (or the owning property/method key) through
/// the parameter-list opening paren.
fn function_head_span(
    semantic: &Semantic<'_>,
    node: &AstNode<'_>,
    parameters: &oxc_ast::ast::FormalParameters<'_>,
    tokens: &[Token],
    function_span: Span,
) -> Span {
    let parent = semantic.nodes().parent_node(node.id());
    let start = match parent.kind() {
        AstKind::ObjectProperty(property) if property.value.span() == function_span => {
            property.span().start
        }
        AstKind::MethodDefinition(definition) if definition.value.span() == function_span => {
            definition.span().start
        }
        AstKind::PropertyDefinition(field)
            if field
                .value
                .as_ref()
                .is_some_and(|value| value.span() == function_span) =>
        {
            field.span().start
        }
        _ => function_span.start,
    };
    let parameter_start = parameters
        .items
        .first()
        .map_or(function_span.start, |parameter| parameter.span().start);
    let index = tokens.partition_point(|token| token.end() <= parameter_start);
    let end = match index
        .checked_sub(1)
        .and_then(|position| tokens.get(position))
    {
        Some(token) if token.kind() == Kind::LParen => token.start(),
        _ => parameter_start,
    };
    Span::new(start, end)
}

fn arrow_token_span(tokens: &[Token], body_start: u32) -> Option<Span> {
    let index = tokens
        .partition_point(|token| token.end() <= body_start)
        .checked_sub(1)?;
    let token = tokens.get(index)?;
    (token.kind() == Kind::Arrow).then(|| Span::new(token.start(), token.end()))
}

fn is_type_predicate(return_type: Option<&TSTypeAnnotation<'_>>) -> bool {
    return_type
        .is_some_and(|annotation| matches!(annotation.type_annotation, TSType::TSTypePredicate(_)))
}

/// The reference `getFunctionNameWithKind`.
fn function_name_with_kind(
    semantic: &Semantic<'_>,
    node: &AstNode<'_>,
    function_span: Span,
    function_id: Option<&BindingIdentifier<'_>>,
    arrow: bool,
) -> String {
    let parent = semantic.nodes().parent_node(node.id());
    let owned: Option<Vec<String>> = match parent.kind() {
        AstKind::ObjectProperty(property) if property.value.span() == function_span => Some(vec![
            "method".into(),
            key_name(&property.key, property.computed),
        ]),
        AstKind::MethodDefinition(definition) if definition.value.span() == function_span => {
            if definition.kind == MethodDefinitionKind::Constructor {
                return "constructor".to_string();
            }
            let mut tokens: Vec<String> = Vec::new();
            if definition.r#static {
                tokens.push("static".into());
            }
            match definition.kind {
                MethodDefinitionKind::Get => tokens.push("getter".into()),
                MethodDefinitionKind::Set => tokens.push("setter".into()),
                _ => tokens.push("method".into()),
            }
            tokens.push(key_name(&definition.key, definition.computed));
            Some(tokens)
        }
        AstKind::PropertyDefinition(field)
            if field
                .value
                .as_ref()
                .is_some_and(|value| value.span() == function_span) =>
        {
            let mut tokens: Vec<String> = Vec::new();
            if field.r#static {
                tokens.push("static".into());
            }
            tokens.push("method".into());
            tokens.push(key_name(&field.key, field.computed));
            Some(tokens)
        }
        _ => None,
    };
    if let Some(tokens) = owned {
        return tokens.join(" ");
    }
    let mut tokens: Vec<String> = Vec::new();
    if arrow {
        tokens.push("arrow".into());
    }
    tokens.push("function".into());
    if let Some(id) = function_id {
        tokens.push(format!("'{}'", id.name));
        return tokens.join(" ");
    }
    if let Some(name) = anonymous_function_name(parent.kind()) {
        tokens.push(name);
    }
    tokens.join(" ")
}

/// The reference fallback names for anonymous functions: the declarator or
/// assignment identifier, or `'default'` for direct default exports.
fn anonymous_function_name(parent: AstKind<'_>) -> Option<String> {
    match parent {
        AstKind::VariableDeclarator(declarator) => match &declarator.id {
            BindingPattern::BindingIdentifier(id) => Some(format!("'{}'", id.name)),
            _ => None,
        },
        AstKind::AssignmentExpression(assignment) => match &assignment.left {
            oxc_ast::ast::AssignmentTarget::AssignmentTargetIdentifier(identifier) => {
                Some(format!("'{}'", identifier.name))
            }
            _ => None,
        },
        AstKind::ExportDefaultDeclaration(_) => Some("'default'".to_string()),
        _ => None,
    }
}

fn key_name(key: &PropertyKey<'_>, computed: bool) -> String {
    if !computed && let PropertyKey::StaticIdentifier(identifier) = key {
        return format!("'{}'", identifier.name);
    }
    match key {
        PropertyKey::StaticIdentifier(identifier) => format!("'{}'", identifier.name),
        PropertyKey::StringLiteral(literal) => format!("'{}'", literal.value),
        PropertyKey::NumericLiteral(literal) => format!("'{}'", literal.value),
        _ => "'?'".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7770_flags_pinned_zod_doc_anchor() {
        // Pinned anchor: colinhacks/zod@46da957 packages/zod/src/v4/core/doc.ts:35
        // `const lines = content.split("\n").filter((x) => x);`
        let source = "\
function doc(content: string) {
  const lines = content.split(\"\\n\").filter((x) => x);
  return lines;
}
";
        let report = ts(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "typescript:S7770"), 1);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "typescript:S7770")
            .expect("pinned zod doc identity filter must be reported");
        assert_eq!(
            issue.message,
            "arrow function is equivalent to `Boolean`. Use `Boolean` directly."
        );
        assert_eq!(issue.range.start.line, 2);
        let prefix = "  const lines = content.split(\"\\n\").filter((x) ";
        assert_eq!(
            issue.range.start.column,
            u32::try_from(prefix.len()).unwrap()
        );
        assert_eq!(
            issue.range.end.column,
            u32::try_from(prefix.len() + "=>".len()).unwrap()
        );
    }

    #[test]
    fn s7770_flags_all_reference_case_families() {
        let source = "\
const list = [];
const a = list.find((v) => v);
const b = list.find((v) => { return v; });
const c = list.every(function check(v) { return v; });
const truthy = (v) => Boolean(v);
const numeric = (v) => { return Number(v); };
function stringify(v) { return String(v); }
const helpers = {
  parse: function (v) { return Boolean(v); },
};
";
        let report = js(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "javascript:S7770"), 7);
        let messages: Vec<&str> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S7770")
            .map(|issue| issue.message.as_str())
            .collect();
        assert!(
            messages
                .contains(&"arrow function is equivalent to `Boolean`. Use `Boolean` directly.")
        );
        assert!(
            messages
                .contains(&"function 'check' is equivalent to `Boolean`. Use `Boolean` directly.")
        );
        assert!(messages.contains(
            &"arrow function 'numeric' is equivalent to `Number`. Use `Number` directly."
        ));
        assert!(
            messages.contains(
                &"function 'stringify' is equivalent to `String`. Use `String` directly."
            )
        );
        assert!(
            messages
                .contains(&"method 'parse' is equivalent to `Boolean`. Use `Boolean` directly.")
        );
    }

    #[test]
    fn s7770_wrapper_and_accessor_boundaries_stay_silent() {
        let source = "\
function shadow() {
  const String = (v) => `${v}`;
  const wrap = (v) => String(v);
  return wrap;
}
function shadowedCallback() {
  const Boolean = (v) => v !== 0;
  const list = [];
  return list.filter((x) => x);
}
const list = [];
const notIdentity = list.filter((x) => x.ok);
const mapped = list.map((x) => x);
const optionalMember = list?.filter((x) => x);
const optionalCall = list.filter?.((x) => x);
const computed = list['filter']((x) => x);
const notFirst = list.filter(check, (x) => x);
const asyncFn = async (v) => Boolean(v);
function* generate(v) { return Boolean(v); }
class Box {
  constructor(v) {
    return Boolean(v);
  }
}
const wrapped = {
  set value(v) {
    return Boolean(v);
  },
};
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7770"), 0);
    }

    #[test]
    fn s7770_type_predicates_and_extra_wrappers() {
        let source = "\
const list: string[] = [];
const typeGuard = list.filter((v): v is string => v);
const wrapper = (v: unknown): boolean => Boolean(v);
";
        let keys = ts_keys(source);
        assert_eq!(count_key(&keys, "typescript:S7770"), 1);
    }

    #[test]
    fn s7770_reports_in_both_languages() {
        let ts_source = "\
declare const list: string[];
const a = list.filter((x) => x);
";
        let js_source = "\
const list = [];
const a = list.filter((x) => x);
";
        assert_eq!(count_key(&js_keys(js_source), "javascript:S7770"), 1);
        assert_eq!(count_key(&ts_keys(ts_source), "typescript:S7770"), 1);
    }
}
