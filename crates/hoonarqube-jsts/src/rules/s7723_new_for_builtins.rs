// Rule module s7723_new_for_builtins (generated).
//
// `typescript:S7723` — Built-in constructors should be called consistently
// with or without "new". Reference semantics: eslint-plugin-unicorn
// `new-for-builtins` wrapped by SonarJS S7723 (which exempts `Object(value)`
// type coercions): calling a `new`-enforcing builtin (for example `Array`,
// `Object`, `Map`, `Date`, `Promise`, `RegExp`, `Intl.*`, typed arrays) as a
// plain function is reported with "Use `new X()` instead of `X()`.", while
// `Date()` carries the dedicated "Use `String(new Date())` instead of
// `Date()`." wording; `new` on a call-only builtin (`BigInt`, `Boolean`,
// `Number`, `String`, `Symbol`) is reported with "Use `X()` instead of
// `new X()`."; `Temporal.Now`, `WebAssembly`, and `WebAssembly.JSTag` are
// neither and are reported as "not a function or constructor" in either
// form. Optional chains, `Object` inside `===`/`!==`, shadowed bindings,
// and correct forms stay silent. Findings span the whole call or `new`
// expression.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{CallExpression, Expression, NewExpression};
use oxc_semantic::Semantic;
use oxc_span::GetSpan;

/// Builtins whose calls require `new`.
const ENFORCE_NEW: &[&str] = &[
    "Object",
    "Array",
    "ArrayBuffer",
    "DataView",
    "Date",
    "Function",
    "Map",
    "WeakMap",
    "Set",
    "WeakSet",
    "Promise",
    "RegExp",
    "SharedArrayBuffer",
    "Proxy",
    "WeakRef",
    "FinalizationRegistry",
    "DisposableStack",
    "AsyncDisposableStack",
    "Error",
    "EvalError",
    "RangeError",
    "ReferenceError",
    "SyntaxError",
    "TypeError",
    "URIError",
    "AggregateError",
    "SuppressedError",
    "Int8Array",
    "Uint8Array",
    "Uint8ClampedArray",
    "Int16Array",
    "Uint16Array",
    "Int32Array",
    "Float16Array",
    "Float32Array",
    "Float64Array",
    "BigInt64Array",
    "BigUint64Array",
];

/// Dotted builtins whose calls require `new`.
const ENFORCE_NEW_DOTTED: &[(&str, &str)] = &[
    ("Intl", "Collator"),
    ("Intl", "DateTimeFormat"),
    ("Intl", "DisplayNames"),
    ("Intl", "DurationFormat"),
    ("Intl", "ListFormat"),
    ("Intl", "Locale"),
    ("Intl", "NumberFormat"),
    ("Intl", "PluralRules"),
    ("Intl", "RelativeTimeFormat"),
    ("Intl", "Segmenter"),
    ("Temporal", "Duration"),
    ("Temporal", "Instant"),
    ("Temporal", "PlainDate"),
    ("Temporal", "PlainDateTime"),
    ("Temporal", "PlainMonthDay"),
    ("Temporal", "PlainTime"),
    ("Temporal", "PlainYearMonth"),
    ("Temporal", "ZonedDateTime"),
    ("WebAssembly", "Module"),
    ("WebAssembly", "Instance"),
    ("WebAssembly", "Memory"),
    ("WebAssembly", "Table"),
    ("WebAssembly", "Global"),
    ("WebAssembly", "Tag"),
    ("WebAssembly", "Exception"),
    ("WebAssembly", "CompileError"),
    ("WebAssembly", "LinkError"),
    ("WebAssembly", "RuntimeError"),
];

/// Builtins that must be called without `new`.
const DISALLOW_NEW: &[&str] = &["BigInt", "Boolean", "Number", "String", "Symbol"];

/// Builtins that are neither function nor constructor.
const DISALLOW_CALL_OR_NEW: &[&str] = &["WebAssembly"];
const DISALLOW_CALL_OR_NEW_DOTTED: &[(&str, &str)] =
    &[("Temporal", "Now"), ("WebAssembly", "JSTag")];

/// Entry point: `typescript:S7723` builtin constructor-style check.
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
            AstKind::CallExpression(call) => {
                check_builtin_call(&mut sink, semantic, node.id(), call);
            }
            AstKind::NewExpression(new) => check_builtin_new(&mut sink, semantic, new),
            _ => {}
        }
    }
    sink.issues
}

/// The dotted path of a global-reference callee: the root identifier for
/// plain callees, the root and property for a one-level static member.
fn global_callee_path<'a>(
    semantic: &Semantic<'a>,
    callee: &Expression<'a>,
) -> Option<(&'a str, Option<&'a str>)> {
    match unparenthesized(callee) {
        Expression::Identifier(identifier) => semantic
            .is_reference_to_global_variable(identifier)
            .then_some(identifier.name.as_str())
            .map(|name| (name, None)),
        Expression::StaticMemberExpression(member) => {
            let Expression::Identifier(root) = &member.object else {
                return None;
            };
            semantic
                .is_reference_to_global_variable(root)
                .then_some(root.name.as_str())
                .map(|name| (name, Some(member.property.name.as_str())))
        }
        _ => None,
    }
}

fn in_plain(list: &[&str], path: (&str, Option<&str>)) -> bool {
    path.1.is_none() && list.contains(&path.0)
}

fn in_dotted(list: &[(&str, &str)], path: (&str, Option<&str>)) -> bool {
    match path {
        (root, Some(property)) => list.contains(&(root, property)),
        (_, None) => false,
    }
}

/// Display name of a callee path (`Object` / `Intl.Collator`).
fn path_display(path: (&str, Option<&str>)) -> String {
    match path.1 {
        Some(property) => format!("{}.{}", path.0, property),
        None => path.0.to_string(),
    }
}

fn check_builtin_call(
    sink: &mut IssueSink,
    semantic: &Semantic<'_>,
    call_node_id: oxc_syntax::node::NodeId,
    call: &CallExpression<'_>,
) {
    if call.optional || has_optional_member(&call.callee) {
        return;
    }
    let Some(path) = global_callee_path(semantic, &call.callee) else {
        return;
    };
    if path == ("Object", None) {
        // The SonarJS decorator exempts `Object(value)` coercions entirely,
        // and the reference rule exempts `Object()` inside `===`/`!==`.
        if !call.arguments.is_empty() || object_in_equality(semantic, call_node_id) {
            return;
        }
    }
    let display = path_display(path);
    if path == ("Date", None) {
        sink.emit_span(
            RuleScope::TsOnly,
            "S7723",
            "Use `String(new Date())` instead of `Date()`.",
            call.span(),
        );
        return;
    }
    if in_plain(ENFORCE_NEW, path) || in_dotted(ENFORCE_NEW_DOTTED, path) {
        sink.emit_span(
            RuleScope::TsOnly,
            "S7723",
            &format!("Use `new {display}()` instead of `{display}()`."),
            call.span(),
        );
        return;
    }
    if in_plain(DISALLOW_CALL_OR_NEW, path) || in_dotted(DISALLOW_CALL_OR_NEW_DOTTED, path) {
        sink.emit_span(
            RuleScope::TsOnly,
            "S7723",
            &format!("`{display}` is not a function or constructor."),
            call.span(),
        );
    }
}

fn check_builtin_new(sink: &mut IssueSink, semantic: &Semantic<'_>, new: &NewExpression<'_>) {
    let Some(path) = global_callee_path(semantic, &new.callee) else {
        return;
    };
    if in_plain(DISALLOW_NEW, path) {
        let display = path_display(path);
        sink.emit_span(
            RuleScope::TsOnly,
            "S7723",
            &format!("Use `{display}()` instead of `new {display}()`."),
            new.span(),
        );
        return;
    }
    if in_plain(DISALLOW_CALL_OR_NEW, path) || in_dotted(DISALLOW_CALL_OR_NEW_DOTTED, path) {
        let display = path_display(path);
        sink.emit_span(
            RuleScope::TsOnly,
            "S7723",
            &format!("`{display}` is not a function or constructor."),
            new.span(),
        );
    }
}

/// Whether the callee chain contains an optional member link
/// (`Intl?.Collator`), which cannot be rewritten to `new`.
fn has_optional_member(expression: &Expression<'_>) -> bool {
    match unparenthesized(expression) {
        Expression::StaticMemberExpression(member) => {
            member.optional || has_optional_member(&member.object)
        }
        Expression::ComputedMemberExpression(member) => has_optional_member(&member.object),
        _ => false,
    }
}

fn object_in_equality(semantic: &Semantic<'_>, call_node_id: oxc_syntax::node::NodeId) -> bool {
    matches!(
        semantic.nodes().parent_kind(call_node_id),
        AstKind::BinaryExpression(binary)
            if crate::rules::shared::is_equality_operator(binary.operator)
    )
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    fn rule_messages(report: &hoonarqube_ir::FileReport) -> Vec<String> {
        report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "typescript:S7723")
            .map(|issue| issue.message.clone())
            .collect()
    }

    #[test]
    fn s7723_flags_pinned_markdownit_array_anchor() {
        // Pinned anchor: markdown-it@3c51991 src/rules_block/hr.ts:38
        // `token.markup = Array(cnt + 1).join(String.fromCharCode(marker))`
        let source = "token.markup = Array(cnt + 1).join(String.fromCharCode(marker));\n";
        let report = ts(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "typescript:S7723"), 1);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "typescript:S7723")
            .expect("pinned markdown-it Array call must be reported");
        assert_eq!(issue.message, "Use `new Array()` instead of `Array()`.");
        assert_eq!(issue.range.start.line, 1);
        assert_eq!(
            issue.range.start.column,
            u32::try_from("token.markup = ".len()).unwrap()
        );
        assert_eq!(
            issue.range.end.column,
            u32::try_from("token.markup = Array(cnt + 1)".len()).unwrap()
        );
    }

    #[test]
    fn s7723_flags_pinned_markdownit_state_inline_anchor() {
        // Pinned anchor: markdown-it@3c51991 src/rules_inline/state_inline.ts:58
        // `this.tokens_meta = Array(outTokens.length)`
        let source = "this.tokens_meta = Array(outTokens.length)\n";
        let keys = ts_keys(source);
        assert_eq!(count_key(&keys, "typescript:S7723"), 1);
        assert_eq!(
            keys.iter().find(|(key, _)| key == "typescript:S7723"),
            Some(&("typescript:S7723".to_string(), 1))
        );
    }

    #[test]
    fn s7723_flags_enforced_builtins_without_new() {
        let source = "\
Object();
Map();
Set();
WeakMap();
Promise(executor);
RegExp('x');
Function('return 1');
Date();
Intl.Collator();
Int8Array(4);
";
        let report = ts(source);
        assert_eq!(count_key(&report_keys(&report), "typescript:S7723"), 10);
        let messages = rule_messages(&report);
        assert!(messages.contains(&"Use `new Object()` instead of `Object()`.".to_string()));
        assert!(messages.contains(&"Use `new Map()` instead of `Map()`.".to_string()));
        assert!(messages.contains(&"Use `String(new Date())` instead of `Date()`.".to_string()));
        assert!(
            messages
                .contains(&"Use `new Intl.Collator()` instead of `Intl.Collator()`.".to_string())
        );
        assert!(messages.contains(&"Use `new Int8Array()` instead of `Int8Array()`.".to_string()));
    }

    #[test]
    fn s7723_reports_disallowed_new_and_not_a_function_forms() {
        let source = "\
new String('x');
new Boolean(true);
new Number(1);
new Symbol('x');
new BigInt(1);
WebAssembly();
new WebAssembly();
new WebAssembly.Module(bytes);
";
        let report = ts(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "typescript:S7723"), 7);
        let messages = rule_messages(&report);
        assert!(messages.contains(&"Use `String()` instead of `new String()`.".to_string()));
        assert!(messages.contains(&"Use `Symbol()` instead of `new Symbol()`.".to_string()));
        assert!(messages.contains(&"`WebAssembly` is not a function or constructor.".to_string()));
    }

    #[test]
    fn s7723_correct_forms_stay_silent() {
        let silent = "\
const literal = [1, 2];
const fresh = new Array(3);
const coerced = Object('boxed');
const primitive = String(5);
const map = new Map();
const now = new Date();
const pattern = new RegExp('x');
";
        assert_eq!(count_key(&ts_keys(silent), "typescript:S7723"), 0);
    }

    #[test]
    fn s7723_object_equality_optional_chain_and_shadowing_stay_silent() {
        let silent = "\
const same = other === Object();
const different = other !== Object();
const lazy = Array?.(3);
const lazy_intl = Intl?.Collator();
function local(Array) {
  return Array(3);
}
";
        assert_eq!(count_key(&ts_keys(silent), "typescript:S7723"), 0);
    }

    #[test]
    fn s7723_stays_silent_in_javascript_files() {
        let source = "const markup = Array(cnt + 1);\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S7723"), 0);
    }
}
