// Rule module s7751_prefer_array_flat (generated).
//
// `javascript:S7751` + `typescript:S7751` — Array flattening should use the
// native "flat()" method. Reference semantics: eslint-plugin-unicorn
// `prefer-array-flat` at the version pinned by SonarJS 13.x (v65.0.1,
// wrapped by SonarJS S7751): one-level flattening through
// `array.flatMap(x => x)`,
// `array.reduce((a, b) => a.concat(b), [])`,
// `array.reduce((a, b) => [...a, ...b], [])`,
// `[].concat(maybeArray)`, `[].concat(...array)`,
// `[].concat.apply([], array)`,
// `Array.prototype.concat.apply([], array)`,
// `Array.prototype.concat.call([], maybeArrayOrSpread)`, and the
// `_.flatten`/`lodash.flatten`/`underscore.flatten` helpers is reported on
// the call. Obvious non-array `flatMap` receivers (PascalCase identifiers
// without a const array initializer, const non-array initializers) stay
// silent; deeper flattening forms (extra `concat` arguments) are outside
// the rule. `[].concat(value)` depth and coercion semantics are preserved:
// no auto-fix is offered because array-like or custom-spreadable receivers
// would change behavior.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{
    Argument, ArrayExpressionElement, BindingPattern, CallExpression, Expression,
    StaticMemberExpression, VariableDeclarationKind,
};
use oxc_semantic::{AstNode, Semantic};

/// Entry point: `javascript:S7751` + `typescript:S7751` prefer-array-flat
/// check over the parsed program. Requires the semantic model for the
/// flatMap receiver guard, so recoverable-parse files stay silent.
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
        if let AstKind::CallExpression(call) = node.kind()
            && let Some(description) = flatten_case_description(semantic, node, call)
        {
            sink.emit_span(
                RuleScope::Both,
                "S7751",
                &format!("Prefer `Array#flat()` over `{description}` to flatten an array."),
                call.span,
            );
        }
    }
    sink.issues
}

/// The reference description of the matched legacy-flattening case, if the
/// call matches one of the supported one-level forms.
fn flatten_case_description<'a>(
    semantic: &Semantic<'a>,
    node: &AstNode<'a>,
    call: &CallExpression<'a>,
) -> Option<&'static str> {
    flat_map_case(semantic, node, call)
        .or_else(|| reduce_case(call))
        .or_else(|| empty_array_concat_case(call))
        .or_else(|| array_prototype_concat_case(call))
        .or_else(|| lodash_flatten_case(call))
}

/// The plain identifier bound by a binding pattern, without descending
/// into assignment patterns (the reference `isSameIdentifier` compares
/// identifier nodes only).
fn pattern_identifier<'a>(pattern: &'a BindingPattern<'a>) -> Option<&'a str> {
    match pattern {
        BindingPattern::BindingIdentifier(identifier) => Some(identifier.name.as_str()),
        _ => None,
    }
}

/// `array.flatMap(x => x)` — plus the obvious non-array receiver guard.
fn flat_map_case<'a>(
    semantic: &Semantic<'a>,
    node: &AstNode<'a>,
    call: &CallExpression<'a>,
) -> Option<&'static str> {
    let member = method_member(call, "flatMap", true)?;
    if call.optional || call.arguments.len() != 1 {
        return None;
    }
    let Some(Expression::ArrowFunctionExpression(arrow)) = call.arguments[0].as_expression() else {
        return None;
    };
    if arrow.r#async || arrow.params.items.len() != 1 || arrow.params.rest.is_some() {
        return None;
    }
    let parameter = pattern_identifier(&arrow.params.items[0].pattern)?;
    let identity_expression = arrow.body.as_expression()?;
    let Expression::Identifier(identity) = unparenthesized(identity_expression) else {
        return None;
    };
    if parameter != identity.name.as_str() {
        return None;
    }
    if is_obviously_non_array_receiver(semantic, node, &member.object) {
        return None;
    }
    Some("Array#flatMap()")
}

/// `array.reduce((a, b) => a.concat(b), [])` and
/// `array.reduce((a, b) => [...a, ...b], [])`.
fn reduce_case(call: &CallExpression<'_>) -> Option<&'static str> {
    method_member(call, "reduce", true)?;
    if call.optional || call.arguments.len() != 2 {
        return None;
    }
    let Some(Expression::ArrowFunctionExpression(arrow)) = call.arguments[0].as_expression() else {
        return None;
    };
    if arrow.r#async || arrow.params.items.len() != 2 || arrow.params.rest.is_some() {
        return None;
    }
    if !argument_is_empty_array(&call.arguments[1]) {
        return None;
    }
    let first = pattern_identifier(&arrow.params.items[0].pattern)?;
    let second = pattern_identifier(&arrow.params.items[1].pattern)?;
    let body = arrow.body.as_expression()?;
    match unparenthesized(body) {
        // `(a, b) => a.concat(b)`
        Expression::CallExpression(concat) => {
            let member = method_member(concat, "concat", false)?;
            if concat.optional || concat.arguments.len() != 1 {
                return None;
            }
            let Expression::Identifier(receiver) = unparenthesized(&member.object) else {
                return None;
            };
            let concat_argument = concat.arguments[0].as_expression()?;
            let Expression::Identifier(argument) = unparenthesized(concat_argument) else {
                return None;
            };
            (receiver.name.as_str() == first && argument.name.as_str() == second)
                .then_some("Array#reduce()")
        }
        // `(a, b) => [...a, ...b]`
        Expression::ArrayExpression(spread) => {
            if spread.elements.len() != 2 {
                return None;
            }
            for (element, name) in spread.elements.iter().zip([first, second]) {
                let ArrayExpressionElement::SpreadElement(spread) = element else {
                    return None;
                };
                let Expression::Identifier(argument) = unparenthesized(&spread.argument) else {
                    return None;
                };
                if argument.name.as_str() != name {
                    return None;
                }
            }
            Some("Array#reduce()")
        }
        _ => None,
    }
}

/// `[].concat(maybeArray)` and `[].concat(...array)`.
fn empty_array_concat_case(call: &CallExpression<'_>) -> Option<&'static str> {
    let member = method_member(call, "concat", false)?;
    if call.optional || call.arguments.len() != 1 {
        return None;
    }
    match unparenthesized(&member.object) {
        Expression::ArrayExpression(array) if array.elements.is_empty() => Some("[].concat()"),
        _ => None,
    }
}

/// `[].concat.apply([], array)`, `[].concat.call([], maybeArrayOrSpread)`,
/// and the `Array.prototype.concat.apply/call` forms.
fn array_prototype_concat_case(call: &CallExpression<'_>) -> Option<&'static str> {
    if call.optional || call.arguments.len() != 2 {
        return None;
    }
    let Expression::StaticMemberExpression(member) = unparenthesized(&call.callee) else {
        return None;
    };
    if member.optional {
        return None;
    }
    let method = member.property.name.as_str();
    if method != "apply" && method != "call" {
        return None;
    }
    let Expression::StaticMemberExpression(concat_member) = unparenthesized(&member.object) else {
        return None;
    };
    if concat_member.optional || concat_member.property.name != "concat" {
        return None;
    }
    let receiver_ok = match unparenthesized(&concat_member.object) {
        // `Array.prototype.concat`
        Expression::StaticMemberExpression(prototype) => {
            !prototype.optional
                && prototype.property.name == "prototype"
                && matches!(
                    unparenthesized(&prototype.object),
                    Expression::Identifier(root) if root.name == "Array"
                )
        }
        // `[].concat`
        receiver => {
            matches!(receiver, Expression::ArrayExpression(array) if array.elements.is_empty())
        }
    };
    if !receiver_ok {
        return None;
    }
    if !argument_is_empty_array(call.arguments.first()?) {
        return None;
    }
    // `apply` needs a plain array; `call` accepts a spread list too.
    if method == "apply" && matches!(call.arguments[1], Argument::SpreadElement(_)) {
        return None;
    }
    Some("Array.prototype.concat()")
}

/// `_.flatten(x)`, `lodash.flatten(x)`, and `underscore.flatten(x)`.
fn lodash_flatten_case(call: &CallExpression<'_>) -> Option<&'static str> {
    if call.optional || call.arguments.len() != 1 {
        return None;
    }
    if matches!(call.arguments[0], Argument::SpreadElement(_)) {
        return None;
    }
    let Expression::StaticMemberExpression(member) = unparenthesized(&call.callee) else {
        return None;
    };
    if member.optional || member.property.name != "flatten" {
        return None;
    }
    let Expression::Identifier(root) = unparenthesized(&member.object) else {
        return None;
    };
    match root.name.as_str() {
        "_" => Some("_.flatten()"),
        "lodash" => Some("lodash.flatten()"),
        "underscore" => Some("underscore.flatten()"),
        _ => None,
    }
}

/// The static member whose non-computed property is `method`.
fn method_member<'a, 'b>(
    call: &'b CallExpression<'a>,
    method: &str,
    allow_optional_member: bool,
) -> Option<&'b StaticMemberExpression<'a>> {
    let Expression::StaticMemberExpression(member) = unparenthesized(&call.callee) else {
        return None;
    };
    if member.property.name != method || (!allow_optional_member && member.optional) {
        return None;
    }
    Some(member)
}

fn argument_is_empty_array(argument: &Argument<'_>) -> bool {
    argument
        .as_expression()
        .map(unparenthesized)
        .is_some_and(|expression| {
            matches!(expression, Expression::ArrayExpression(array) if array.elements.is_empty())
        })
}

/// The reference flatMap guard: a `PascalCase` receiver without a const array
/// initializer, or a const receiver initialized with a known non-array.
fn is_obviously_non_array_receiver(
    semantic: &Semantic<'_>,
    call_node: &AstNode<'_>,
    receiver: &Expression<'_>,
) -> bool {
    let Expression::Identifier(identifier) = unparenthesized(receiver) else {
        return false;
    };
    let initializer = const_variable_initializer(semantic, call_node, identifier);
    let pascal_case = identifier
        .name
        .as_str()
        .chars()
        .next()
        .is_some_and(char::is_uppercase);
    if pascal_case && !initializer.is_some_and(is_definitely_array) {
        return true;
    }
    initializer.is_some_and(is_definitely_non_array)
}

/// The initializer of a `const` binding with exactly one declaration, like
/// the reference `getConstVariableInitializer` lookup.
fn const_variable_initializer<'a>(
    semantic: &Semantic<'a>,
    call_node: &AstNode<'a>,
    identifier: &'a oxc_ast::ast::IdentifierReference<'a>,
) -> Option<&'a Expression<'a>> {
    let symbol = semantic
        .scoping()
        .find_binding(call_node.scope_id(), identifier.name)?;
    if semantic.scoping().symbol_declarations(symbol).count() != 1 {
        return None;
    }
    let declarator_node = semantic.symbol_declaration(symbol);
    let AstKind::VariableDeclarator(declarator) = declarator_node.kind() else {
        return None;
    };
    let init = declarator.init.as_ref()?;
    let AstKind::VariableDeclaration(declaration) =
        semantic.nodes().parent_kind(declarator_node.id())
    else {
        return None;
    };
    (declaration.kind == VariableDeclarationKind::Const).then_some(init)
}

fn is_definitely_array(initializer: &Expression<'_>) -> bool {
    match unparenthesized(initializer) {
        Expression::ArrayExpression(_) => true,
        Expression::NewExpression(new) => {
            matches!(unparenthesized(&new.callee), Expression::Identifier(root) if root.name == "Array")
        }
        _ => false,
    }
}

fn is_definitely_non_array(initializer: &Expression<'_>) -> bool {
    match unparenthesized(initializer) {
        Expression::ObjectExpression(_)
        | Expression::StringLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::BooleanLiteral(_)
        | Expression::NullLiteral(_)
        | Expression::BigIntLiteral(_)
        | Expression::RegExpLiteral(_)
        | Expression::TemplateLiteral(_)
        | Expression::ArrowFunctionExpression(_)
        | Expression::FunctionExpression(_)
        | Expression::ClassExpression(_) => true,
        Expression::NewExpression(new) => {
            matches!(unparenthesized(&new.callee), Expression::Identifier(root) if root.name != "Array")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7751_flags_pinned_express_view_anchor() {
        // Pinned anchor: expressjs/express lib/view.js:106
        // `var roots = [].concat(this.root);` (the full pinned SHA in the
        // issue text is garbled upstream; the content anchor is verified at
        // the express default branch HEAD 3ce6d0eb).
        let source = "\
function lookup(name) {
  var path;
  var roots = [].concat(this.root);

  debug('lookup \"%s\"', name);

  return path;
}
";
        let report = js(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "javascript:S7751"), 1);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "javascript:S7751")
            .expect("pinned express view roots must be reported");
        assert_eq!(
            issue.message,
            "Prefer `Array#flat()` over `[].concat()` to flatten an array."
        );
        assert_eq!(issue.range.start.line, 3);
        assert_eq!(
            issue.range.start.column,
            u32::try_from("  var roots = ".len()).unwrap()
        );
        assert_eq!(issue.range.end.line, 3);
        assert_eq!(
            issue.range.end.column,
            u32::try_from("  var roots = [].concat(this.root)".len()).unwrap()
        );
    }

    #[test]
    fn s7751_flags_all_reference_case_families() {
        let source = "\
const array = [[1], [2]];
const other = [].concat(...array);
const applied = [].concat.apply([], array);
const protoApplied = Array.prototype.concat.apply([], array);
const protoCalled = Array.prototype.concat.call([], array);
const directCalled = [].concat.call([], array);
const flatMapped = array.flatMap((x) => x);
const reduced = array.reduce((a, b) => a.concat(b), []);
const spreadReduced = array.reduce((a, b) => [...a, ...b], []);
const lodashFlat = _.flatten(array);
const underscoreFlat = underscore.flatten(array);
";
        let keys = ts_keys(source);
        assert_eq!(count_key(&keys, "typescript:S7751"), 10);
        let report = ts(source);
        let descriptions: Vec<&str> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "typescript:S7751")
            .map(|issue| issue.message.as_str())
            .collect();
        assert!(
            descriptions
                .contains(&"Prefer `Array#flat()` over `Array#flatMap()` to flatten an array.")
        );
        assert!(
            descriptions
                .contains(&"Prefer `Array#flat()` over `Array#reduce()` to flatten an array.")
        );
        assert!(descriptions.contains(
            &"Prefer `Array#flat()` over `Array.prototype.concat()` to flatten an array."
        ));
        assert!(
            descriptions.contains(&"Prefer `Array#flat()` over `_.flatten()` to flatten an array.")
        );
        assert!(
            descriptions.contains(
                &"Prefer `Array#flat()` over `underscore.flatten()` to flatten an array."
            )
        );
    }

    #[test]
    fn s7751_obvious_non_array_flatmap_receivers_stay_silent() {
        let silent = "\
const options = { flatMap: [1] };
options.flatMap((x) => x);
const label = \"str\";
label.flatMap((x) => x);
class Collector {}
const collector = new Collector();
collector.flatMap((x) => x);
function wrap(Param) {
  return Param.flatMap((x) => x);
}
";
        assert_eq!(count_key(&ts_keys(silent), "typescript:S7751"), 0);
    }

    #[test]
    fn s7751_deeper_and_non_matching_forms_stay_silent() {
        let silent = "\
const array = [[1]];
const pair = [].concat(array, array);
const none = [].concat();
const own = array.concat(array);
const chained = own.concat(array);
const deep = _.flattenDeep(array);
const bare = flatten(array);
const spreadLodash = _.flatten(...array);
const asyncMapped = array.flatMap(async (x) => x);
const twoArgs = array.flatMap((x) => x, null);
const notIdentity = array.flatMap((x) => [x]);
";
        assert_eq!(count_key(&ts_keys(silent), "typescript:S7751"), 0);
    }

    #[test]
    fn s7751_flags_optional_chain_and_const_array_receivers() {
        let source = "\
const maybe = [[1]];
const flattened = maybe?.flatMap((x) => x);
";
        assert_eq!(count_key(&ts_keys(source), "typescript:S7751"), 1);
    }

    #[test]
    fn s7751_reports_in_both_languages() {
        let ts_source = "\
declare const array: number[][];
const first = [].concat(array);
";
        let js_source = "\
const array = [[1]];
const first = [].concat(array);
";
        assert_eq!(count_key(&js_keys(js_source), "javascript:S7751"), 1);
        assert_eq!(count_key(&ts_keys(ts_source), "typescript:S7751"), 1);
    }
}
