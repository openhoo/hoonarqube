// Rule module s7764_prefer_global_this (generated).
//
// `javascript:S7764` + `typescript:S7764` — `globalThis` should be used
// instead of `window`, `self`, or `global`. Reference semantics:
// eslint-plugin-unicorn `prefer-global-this` at the version pinned by
// SonarJS 13.x (v65.0.1, wrapped by SonarJS S7764): every reference to an
// unbound `window`, `self`, or `global` identifier is reported on the
// identifier with "Prefer `globalThis` over `<name>`." — except `typeof
// window`/`typeof self`/`typeof global`, which report "Prefer
// `globalThis.<name>` over `<name>`." because the fix keeps the property
// probe semantics.
//
// `window` references are additionally skipped when they address a
// window-specific surface: `window[…]` computed access, `'api' in window`
// existence checks for a window-specific API name, and `window.<api>`
// where `<api>` is in the reference's window-specific API set (the
// `windowSpecificApis` list: window object properties like `top`,
// `frames`, `postMessage`, `open`, `close`, `event`, `screen`, scroll and
// geometry members, `on<event>` handlers for the window-specific events,
// and `addEventListener`/`removeEventListener`/`dispatchEvent` calls whose
// first argument is one of those events).
//
// Locally bound `window`/`self`/`global` names stay silent (the reference
// only sees global-scope variables and unresolved references; the
// single-file subset reports unresolved references only). The reference
// is fixable; no auto-fix is offered here.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{BinaryOperator, Expression};
use oxc_semantic::{AstNode, Semantic};
use oxc_span::GetSpan;

/// Window-specific events (`on<event>` handlers and listener arguments).
const WINDOW_SPECIFIC_EVENTS: [&str; 14] = [
    "resize",
    "blur",
    "focus",
    "load",
    "scroll",
    "scrollend",
    "wheel",
    "beforeunload",
    "message",
    "messageerror",
    "pagehide",
    "pagereveal",
    "pageshow",
    "pageswap",
];

/// Window-specific APIs (the reference `windowSpecificApis` set minus the
/// generated `on*` entries, which are checked separately).
const WINDOW_SPECIFIC_APIS: [&str; 45] = [
    "name",
    "locationbar",
    "menubar",
    "personalbar",
    "scrollbars",
    "statusbar",
    "toolbar",
    "status",
    "close",
    "closed",
    "stop",
    "focus",
    "blur",
    "frames",
    "length",
    "top",
    "opener",
    "parent",
    "frameElement",
    "open",
    "originAgentCluster",
    "postMessage",
    "navigation",
    "addEventListener",
    "removeEventListener",
    "dispatchEvent",
    "event",
    "screen",
    "visualViewport",
    "moveTo",
    "moveBy",
    "resizeTo",
    "resizeBy",
    "innerWidth",
    "innerHeight",
    "outerWidth",
    "outerHeight",
    "scrollX",
    "pageXOffset",
    "scrollY",
    "pageYOffset",
    "scroll",
    "scrollTo",
    "scrollBy",
    "screenX",
];

/// Remaining window-specific APIs (kept under the line-length limit).
const WINDOW_SPECIFIC_APIS_REST: [&str; 6] = [
    "screenLeft",
    "screenY",
    "screenTop",
    "screenWidth",
    "screenHeight",
    "devicePixelRatio",
];

/// Entry point: `javascript:S7764` + `typescript:S7764` prefer-global-this
/// check over the parsed program. Requires the semantic model for
/// unresolved-reference detection, so recoverable-parse files stay silent.
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
        let AstKind::IdentifierReference(identifier) = node.kind() else {
            continue;
        };
        if !matches!(identifier.name.as_str(), "window" | "self" | "global") {
            continue;
        }
        let Some(reference_id) = identifier.reference_id.get() else {
            continue;
        };
        if semantic
            .scoping()
            .get_reference(reference_id)
            .symbol_id()
            .is_some()
        {
            continue;
        }
        if identifier.name == "window" && is_window_specific_usage(semantic, node) {
            continue;
        }
        let (replacement, value) = if is_typeof_argument(semantic, node) {
            (
                format!("globalThis.{}", identifier.name),
                identifier.name.to_string(),
            )
        } else {
            ("globalThis".to_string(), identifier.name.to_string())
        };
        sink.emit_span(
            RuleScope::Both,
            "S7764",
            &format!("Prefer `{replacement}` over `{value}`."),
            identifier.span(),
        );
    }
    sink.issues
}

/// The nearest ancestor that is not a parenthesized expression, mirroring
/// the parent links of the paren-free reference AST.
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

/// `typeof <identifier>` where the identifier is the direct argument.
fn is_typeof_argument(semantic: &Semantic<'_>, node: &AstNode<'_>) -> bool {
    let span = node.kind().span();
    let Some(parent) = significant_parent(semantic, node) else {
        return false;
    };
    match parent.kind() {
        AstKind::UnaryExpression(unary) => {
            unary.operator == oxc_ast::ast::UnaryOperator::Typeof && unary.argument.span() == span
        }
        _ => false,
    }
}

/// The reference `window` exclusions: computed access, `in` existence
/// checks, and window-specific member access.
fn is_window_specific_usage(semantic: &Semantic<'_>, node: &AstNode<'_>) -> bool {
    let span = node.kind().span();
    let Some(parent) = significant_parent(semantic, node) else {
        return false;
    };
    match parent.kind() {
        AstKind::ComputedMemberExpression(member) => member.object.span() == span,
        AstKind::BinaryExpression(binary) => {
            binary.operator == BinaryOperator::In
                && binary.right.span() == span
                && static_property_name(&binary.left).is_some_and(is_window_specific_api)
        }
        AstKind::StaticMemberExpression(member) => {
            member.object.span() == span && is_window_specific_member(semantic, parent, member)
        }
        _ => false,
    }
}

/// `window.<api>` where `<api>` is window-specific; listener calls only
/// count when the first argument is a window-specific event name.
fn is_window_specific_member(
    semantic: &Semantic<'_>,
    member_node: &AstNode<'_>,
    member: &oxc_ast::ast::StaticMemberExpression<'_>,
) -> bool {
    let name = member.property.name.as_str();
    if !is_window_specific_api(name) {
        return false;
    }
    if matches!(
        name,
        "addEventListener" | "removeEventListener" | "dispatchEvent"
    ) {
        let Some(call_node) = significant_parent(semantic, member_node) else {
            return false;
        };
        let AstKind::CallExpression(call) = call_node.kind() else {
            return false;
        };
        if call.callee.span() != member.span {
            return false;
        }
        return call
            .arguments
            .first()
            .and_then(|argument| argument.as_expression())
            .and_then(|expression| match unparenthesized(expression) {
                Expression::StringLiteral(literal) => Some(literal.value.as_str()),
                _ => None,
            })
            .is_some_and(|event| WINDOW_SPECIFIC_EVENTS.contains(&event));
    }
    true
}

/// Whether `name` is in the reference `windowSpecificApis` set (including
/// the generated `on<event>` handlers).
fn is_window_specific_api(name: &str) -> bool {
    if WINDOW_SPECIFIC_APIS.contains(&name) || WINDOW_SPECIFIC_APIS_REST.contains(&name) {
        return true;
    }
    name.strip_prefix("on")
        .is_some_and(|event| WINDOW_SPECIFIC_EVENTS.contains(&event))
}

/// A string literal or expression-free template literal's text.
fn static_property_name<'a>(expression: &'a Expression<'a>) -> Option<&'a str> {
    match unparenthesized(expression) {
        Expression::StringLiteral(literal) => Some(literal.value.as_str()),
        Expression::TemplateLiteral(template) if template.expressions.is_empty() => template
            .quasis
            .first()
            .and_then(|quasi| quasi.value.cooked.as_deref()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7764_flags_global_object_references() {
        let source = "\
const config = window.APP_CONFIG;
window.myGlobalVar = 'value';
const worker = self;
const proc = global.process;
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S7764"), 4);
    }

    #[test]
    fn s7764_flags_typescript_too() {
        let source = "const w: number = window.innerWidth + self.length;\n";
        // `innerWidth`/`length` are window-specific APIs on `window`, but
        // `self.length` is not exempted (only `window` has the API list).
        assert_eq!(count_key(&ts_keys(source), "typescript:S7764"), 1);
    }

    #[test]
    fn s7764_skips_window_specific_apis() {
        let source = "\
window.addEventListener('resize', handler);
window.removeEventListener('message', handler);
window.top.focus();
const isOpen = 'closed' in window;
const value = window['custom'];
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S7764"), 0);
    }

    #[test]
    fn s7764_flags_typeof_with_property_replacement() {
        let report = js("const t = typeof window;\n");
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "javascript:S7764")
            .expect("typeof window must be reported");
        assert_eq!(issue.message, "Prefer `globalThis.window` over `window`.");
    }

    #[test]
    fn s7764_flags_non_specific_window_and_bound_names_stay_silent() {
        let source = "\
window.addEventListener('click', handler);
const doc = window.document;
function f(window) { return window.x; }
const self = { a: 1 };
self.a;
";
        let keys = js_keys(source);
        // `click` is not a window-specific event; `document` is not a
        // window-specific API; the bound `window`/`self` stay silent.
        assert_eq!(count_key(&keys, "javascript:S7764"), 2);
    }
}
