// Rule module s7727_array_callback_reference (generated).
//
// `javascript:S7727` + `typescript:S7727` — eslint-plugin-unicorn
// `no-array-callback-reference` (v65.0.1, wrapped by SonarJS S7727,
// default options): a function reference passed directly as the first
// argument of an iterator method call is reported on the callback node
// with "Do not pass function `X` directly to `.method(…)`." (or "Do not
// pass function directly…" for non-identifier callbacks). Covered
// methods: `every`, `filter`, `find`, `findLast`, `findIndex`,
// `findLastIndex`, `flatMap`, `forEach`, `map`, `reduce`, `reduceRight`,
// `some`. The call must be a non-optional, non-computed member call with
// one or two arguments. Conditional first arguments report each branch
// independently.
//
// Reference exclusions mirrored here: inline functions and arrows,
// `CallExpression` callbacks (including `fn.bind(...)`), values that
// cannot be functions (literals, arrays, objects, binary/unary/update
// expressions, `this`, `await`/`new`/tagged-template/assignment
// expressions, `undefined`), the per-method built-in ignores (`Boolean`
// for every/filter/find*/some; `String`/`Number`/`BigInt`/`Boolean`/
// `Symbol` for `map`), calls whose receiver matches the default ignored
// callee list (`Promise`, `React.Children`, `Children`, `lodash`,
// `underscore`, `_`, `Async`, `async`, `this`, `$`, `jQuery`) or whose
// receiver is a call on one of those callees, `Vue.filter`, `types.map`,
// and non-`reduce*` calls that are the argument of an `await`
// expression. TypeScript type-predicate callbacks on `every`/`filter`/
// `find`/`findLast` stay silent (local function declarations with a
// `x is T` return type, parameters annotated with a predicate function
// type, variables initialized to predicate arrows, and — conservatively,
// like the reference — imported bindings). No auto-fix is offered.
//
// SonarJS reports the rule with scope MAIN: test files (the pinned
// server's filename-based classification, shared with the analyzer's
// other rules) stay silent.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, is_test_file, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{CallExpression, Expression, IdentifierReference};
use oxc_semantic::Semantic;
use oxc_span::GetSpan;
use oxc_syntax::symbol::SymbolId;

/// Iterator methods covered by the reference rule.
const ITERATOR_METHODS: [&str; 12] = [
    "every",
    "filter",
    "find",
    "findLast",
    "findIndex",
    "findLastIndex",
    "flatMap",
    "forEach",
    "map",
    "reduce",
    "reduceRight",
    "some",
];

/// Methods whose TypeScript lib signatures have dedicated type-predicate
/// overloads; predicate callbacks stay silent there.
const TYPE_PREDICATE_METHODS: [&str; 4] = ["every", "filter", "find", "findLast"];

/// Built-in callback names ignored per method (the reference `ignore`
/// lists; `map` adds the primitive wrappers).
fn builtin_ignored(method: &str, name: &str) -> bool {
    match method {
        "map" => matches!(name, "String" | "Number" | "BigInt" | "Boolean" | "Symbol"),
        "every" | "filter" | "find" | "findLast" | "findIndex" | "findLastIndex" | "some" => {
            name == "Boolean"
        }
        _ => false,
    }
}

/// Default ignored callee dotted paths (the reference
/// `defaultIgnoredCallees`; the `ignore` option is empty under `SonarJS`).
const IGNORED_CALLEES: [&str; 11] = [
    "Promise",
    "React.Children",
    "Children",
    "lodash",
    "underscore",
    "_",
    "Async",
    "async",
    "this",
    "$",
    "jQuery",
];

/// Entry point: `javascript:S7727` + `typescript:S7727`
/// no-array-callback-reference check over the parsed program.
pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut sink = IssueSink {
        index: ctx.index,
        language: ctx.language,
        issues: Vec::new(),
    };
    if is_test_file(ctx.path) {
        // Scope MAIN: the pinned server classifies by filename.
        return sink.issues;
    }
    let Some(semantic) = ctx.semantic else {
        return sink.issues;
    };
    for node in semantic.nodes().iter() {
        let AstKind::CallExpression(call) = node.kind() else {
            continue;
        };
        check_call(&mut sink, semantic, node.id(), call);
    }
    sink.issues
}

fn check_call(
    sink: &mut IssueSink<'_>,
    semantic: &Semantic<'_>,
    call_node: oxc_syntax::node::NodeId,
    call: &CallExpression<'_>,
) {
    // `isMethodCall`: non-optional member call, non-computed property,
    // one or two arguments.
    if call.optional || call.arguments.is_empty() || call.arguments.len() > 2 {
        return;
    }
    let Expression::StaticMemberExpression(member) = &call.callee else {
        return;
    };
    if member.optional {
        return;
    }
    let method = member.property.name.as_str();
    if !ITERATOR_METHODS.contains(&method) {
        return;
    }
    if should_ignore_call_expression(semantic, call_node, call, method) {
        return;
    }
    let Some(first) = call.arguments.first() else {
        return;
    };
    let Some(first_expression) = first.as_expression() else {
        // SpreadElement callbacks are not reportable.
        return;
    };
    for callback in ternary_branches(first_expression) {
        if should_ignore_callback(semantic, callback, method) {
            continue;
        }
        let message = match unparenthesized(callback) {
            Expression::Identifier(identifier) => format!(
                "Do not pass function `{}` directly to `.{}(…)`.",
                identifier.name, method
            ),
            _ => format!("Do not pass function directly to `.{method}(…)`."),
        };
        sink.emit_span(RuleScope::Both, "S7727", &message, callback.span());
    }
}

/// The reference `shouldIgnoreCallExpression`: `await`ed calls (except
/// `reduce`/`reduceRight`), ignored callee receivers (including a
/// receiver that is itself a call on an ignored callee), `Vue.filter`,
/// and `types.map`.
fn should_ignore_call_expression(
    semantic: &Semantic<'_>,
    call_node: oxc_syntax::node::NodeId,
    call: &CallExpression<'_>,
    method: &str,
) -> bool {
    if method != "reduce"
        && method != "reduceRight"
        && matches!(
            semantic.nodes().parent_kind(call_node),
            AstKind::AwaitExpression(_)
        )
    {
        return true;
    }
    let Expression::StaticMemberExpression(member) = &call.callee else {
        return true;
    };
    if node_matches_any(&member.object, &IGNORED_CALLEES) {
        return true;
    }
    if let Expression::CallExpression(receiver_call) = unparenthesized(&member.object)
        && node_matches_any(&receiver_call.callee, &IGNORED_CALLEES)
    {
        return true;
    }
    // `Vue.filter(…)` and `types.map(…)` per-method exemptions.
    match method {
        "filter" => matches!(
            unparenthesized(&member.object),
            Expression::Identifier(object) if object.name == "Vue"
        ),
        "map" => matches!(
            unparenthesized(&member.object),
            Expression::Identifier(object) if object.name == "types"
        ),
        _ => false,
    }
}

/// The reference `isNodeMatchesNameOrPath`: a dotted path matched
/// against a member chain; the base may be an identifier, `this`, or
/// `super`, and `meta.property` counts as a two-part path.
fn node_matches_path(expression: &Expression<'_>, path: &str) -> bool {
    let names: Vec<&str> = path.trim().split('.').collect();
    if names.iter().any(|name| name.is_empty()) {
        return false;
    }
    let mut current = expression;
    for (index, name) in names.iter().enumerate().rev() {
        if index == 0 {
            return path_base_matches(current, name);
        }
        if let Some(matched) = meta_property_matches(current, index, name, names[0]) {
            return matched;
        }
        match unparenthesized(current) {
            Expression::StaticMemberExpression(member)
                if !member.optional && member.property.name == *name =>
            {
                current = &member.object;
            }
            _ => return false,
        }
    }
    false
}

/// The leftmost path segment: an identifier, `this`, or `super`.
fn path_base_matches(expression: &Expression<'_>, name: &str) -> bool {
    match unparenthesized(expression) {
        Expression::Identifier(identifier) => identifier.name == name,
        Expression::ThisExpression(_) => name == "this",
        Expression::Super(_) => name == "super",
        _ => false,
    }
}

/// `import.meta`/`new.target` (estree MetaProperty): the property name is
/// fixed, so a two-part path like `import.meta` matches when the remaining
/// name is `import`/`new`. Returns `Some(result)` when `current` is such a
/// meta node, `None` to continue ordinary member matching.
fn meta_property_matches(
    expression: &Expression<'_>,
    index: usize,
    name: &str,
    first: &str,
) -> Option<bool> {
    if index != 1 {
        return None;
    }
    if matches!(unparenthesized(expression), Expression::ImportMeta(_) if name == "meta") {
        return Some(first == "import");
    }
    if matches!(unparenthesized(expression), Expression::NewTarget(_) if name == "target") {
        return Some(first == "new");
    }
    None
}

fn node_matches_any(expression: &Expression<'_>, paths: &[&str]) -> bool {
    paths.iter().any(|path| node_matches_path(expression, path))
}

/// `getTernaryConsequentAndALternate`: each branch of nested conditional
/// expressions is a separate reportable callback.
fn ternary_branches<'a>(expression: &'a Expression<'a>) -> Vec<&'a Expression<'a>> {
    match unparenthesized(expression) {
        Expression::ConditionalExpression(conditional) => {
            let mut branches = ternary_branches(&conditional.consequent);
            branches.extend(ternary_branches(&conditional.alternate));
            branches
        }
        other => vec![other],
    }
}

/// The reference `shouldIgnoreCallback`: inline functions, call results,
/// per-method built-ins, statically-not-a-function values, and
/// type-predicate callbacks on predicate-overload methods.
fn should_ignore_callback(
    semantic: &Semantic<'_>,
    callback: &Expression<'_>,
    method: &str,
) -> bool {
    let callback = unparenthesized(callback);
    match callback {
        Expression::FunctionExpression(_)
        | Expression::ArrowFunctionExpression(_)
        // All CallExpressions are ignored, including `fn.bind()`.
        | Expression::CallExpression(_) => return true,
        Expression::Identifier(identifier)
            if builtin_ignored(method, identifier.name.as_str()) =>
        {
            return true;
        }
        _ => {}
    }
    if is_node_value_not_function(callback) {
        return true;
    }
    TYPE_PREDICATE_METHODS.contains(&method) && is_type_predicate_callback(semantic, callback)
}

/// The reference `isNodeValueNotFunction`: node kinds that cannot (or
/// most likely do not) evaluate to a function.
fn is_node_value_not_function(expression: &Expression<'_>) -> bool {
    match unparenthesized(expression) {
        // Impossible node types.
        Expression::ArrayExpression(_)
        | Expression::BinaryExpression(_)
        | Expression::ClassExpression(_)
        | Expression::ObjectExpression(_)
        | Expression::TemplateLiteral(_)
        | Expression::UnaryExpression(_)
        | Expression::UpdateExpression(_)
        | Expression::BooleanLiteral(_)
        | Expression::NullLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::BigIntLiteral(_)
        | Expression::RegExpLiteral(_)
        | Expression::StringLiteral(_)
        // Most-likely-not node types.
        | Expression::AssignmentExpression(_)
        | Expression::AwaitExpression(_)
        | Expression::NewExpression(_)
        | Expression::TaggedTemplateExpression(_)
        | Expression::ThisExpression(_) => true,
        Expression::Identifier(identifier) => identifier.name == "undefined",
        _ => false,
    }
}

/// The reference `isTypePredicateCallback` (syntax-only subset): a local
/// function declaration with a `x is T` return type, a parameter
/// annotated with a predicate function type, a variable initialized to a
/// predicate arrow/function, or — conservatively — an imported binding.
fn is_type_predicate_callback(semantic: &Semantic<'_>, callback: &Expression<'_>) -> bool {
    let Expression::Identifier(identifier) = unparenthesized(callback) else {
        return false;
    };
    let Some(symbol) = reference_symbol(semantic, identifier) else {
        return false;
    };
    let mut declarations = semantic.scoping().symbol_declarations(symbol);
    let Some(declaration) = declarations.next() else {
        return false;
    };
    match semantic.nodes().get_node(declaration).kind() {
        // `function f(x): x is T` — FunctionName definition.
        AstKind::Function(function) => function
            .return_type
            .as_ref()
            .is_some_and(|annotation| is_type_predicate_annotation(&annotation.type_annotation)),
        // Imported callbacks may be type guards; be conservative.
        AstKind::ImportSpecifier(_)
        | AstKind::ImportDefaultSpecifier(_)
        | AstKind::ImportNamespaceSpecifier(_) => true,
        AstKind::VariableDeclarator(declarator) => {
            if annotation_has_predicate_type(declarator.type_annotation.as_deref()) {
                return true;
            }
            let Some(init) = declarator.init.as_ref() else {
                return false;
            };
            match unparenthesized(init) {
                Expression::ArrowFunctionExpression(arrow) => {
                    arrow.return_type.as_ref().is_some_and(|annotation| {
                        is_type_predicate_annotation(&annotation.type_annotation)
                    })
                }
                Expression::FunctionExpression(function) => {
                    function.return_type.as_ref().is_some_and(|annotation| {
                        is_type_predicate_annotation(&annotation.type_annotation)
                    })
                }
                _ => false,
            }
        }
        // Parameter definition: `cb: (x) => x is T`.
        AstKind::FormalParameter(parameter) => {
            annotation_has_predicate_type(parameter.type_annotation.as_deref())
        }
        _ => false,
    }
}

/// Whether a type annotation is a predicate function type
/// (`cb: (x) => x is T`).
fn annotation_has_predicate_type(annotation: Option<&oxc_ast::ast::TSTypeAnnotation<'_>>) -> bool {
    let Some(annotation) = annotation else {
        return false;
    };
    matches!(
        &annotation.type_annotation,
        oxc_ast::ast::TSType::TSFunctionType(function)
            if is_type_predicate_annotation(&function.return_type.type_annotation)
    )
}

/// Whether a type annotation is a `x is T` predicate.
fn is_type_predicate_annotation(ts_type: &oxc_ast::ast::TSType<'_>) -> bool {
    matches!(ts_type, oxc_ast::ast::TSType::TSTypePredicate(_))
}

/// Symbol a resolved identifier reference points at; `None` for
/// unresolved (global) references.
fn reference_symbol(
    semantic: &Semantic<'_>,
    identifier: &IdentifierReference<'_>,
) -> Option<SymbolId> {
    identifier
        .reference_id
        .get()
        .and_then(|reference_id| semantic.scoping().get_reference(reference_id).symbol_id())
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7727_flags_pinned_exceljs_sites() {
        // Pinned oracle: exceljs@5bed18b lib/doc/worksheet.js:839
        // (`this.conditionalFormattings.filter(filter)`),
        // lib/stream/xlsx/sheet-rels-writer.js:42
        // (`this._hyperlinks.forEach(fn)`), lib/utils/under-dash.js
        // (`obj.forEach(cb)` / `obj.some(cb)` / `obj.every(cb)` /
        // `obj.map(cb)`).
        let source = "\
this.conditionalFormattings = this.conditionalFormattings.filter(filter);
this._hyperlinks.forEach(fn);
obj.forEach(cb);
obj.some(cb);
obj.every(cb);
obj.map(cb);
";
        let findings = js_keys(source);
        assert_eq!(count_key(&findings, "javascript:S7727"), 6);
        let issue = js(source)
            .issues
            .into_iter()
            .find(|issue| issue.rule_key == "javascript:S7727")
            .expect("pinned exceljs filter reference must be reported");
        assert_eq!(
            issue.message,
            "Do not pass function `filter` directly to `.filter(…)`."
        );
        // Report node: the callback identifier `filter`.
        assert_eq!(issue.range.start.line, 1);
        assert_eq!(
            issue.range.start.column,
            u32::try_from(
                "this.conditionalFormattings = this.conditionalFormattings.filter(".len()
            )
            .unwrap()
        );
    }

    #[test]
    fn s7727_flags_member_and_ternary_callbacks() {
        let source = "\
items.map(obj.helper);
items.map(flag ? onItem : other);
";
        let findings = js_keys(source);
        assert_eq!(count_key(&findings, "javascript:S7727"), 3);
        let messages: Vec<String> = js(source)
            .issues
            .into_iter()
            .filter(|issue| issue.rule_key == "javascript:S7727")
            .map(|issue| issue.message)
            .collect();
        assert!(messages.contains(&"Do not pass function directly to `.map(…)`.".to_string()));
        assert!(
            messages.contains(&"Do not pass function `onItem` directly to `.map(…)`.".to_string())
        );
    }

    #[test]
    fn s7727_inline_bind_call_and_builtin_callbacks_stay_silent() {
        let source = "\
items.map(item => item.id);
items.map(function (item) { return item.id; });
items.map(handler.bind(this));
items.filter(Boolean);
items.map(String);
items.map(Number);
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7727"), 0);
    }

    #[test]
    fn s7727_ignored_receivers_and_await_stay_silent() {
        let source = "\
Promise.map(items, load);
_.map(items, load);
lodash.map(items, load);
this.map(load);
React.Children.map(children, render);
$(items).map(load);
async function f() { await items.map(load); }
Vue.filter(items, load);
types.map(nodes, visit);
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7727"), 0);
    }

    #[test]
    fn s7727_non_function_values_and_wrong_calls_stay_silent() {
        let source = "\
items.map(42);
items.map('name');
items.map([fn]);
items.map({ cb: fn });
items.map(a + b);
items.map(undefined);
items.map(this);
items.map(fn, thisArg, extra);
items?.map(fn);
items['map'](fn);
items.notAMethod(fn);
items.map();
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7727"), 0);
    }

    #[test]
    fn s7727_typescript_uses_typescript_key() {
        let source = "items.map(load);\n";
        let findings = ts_keys(source);
        assert_eq!(count_key(&findings, "typescript:S7727"), 1);
        assert_eq!(count_key(&findings, "javascript:S7727"), 0);
    }

    #[test]
    fn s7727_test_files_stay_silent() {
        let source = "items.map(load);\n";
        assert_eq!(count_key(&test_file_keys(source), "javascript:S7727"), 0);
    }
}
