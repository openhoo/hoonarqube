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
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

#[cfg(test)]
mod tests {
    use crate::test_support::*;

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
        assert_eq!(issue.range.start.column, "token.markup = ".len() as u32);
        assert_eq!(
            issue.range.end.column,
            "token.markup = Array(cnt + 1)".len() as u32
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
        let messages = filtered(&report, "typescript:S7723");
        assert!(messages.contains(&"Use `new Object()` instead of `Object()`.".to_string()));
        assert!(messages.contains(&"Use `new Map()` instead of `Map()`.".to_string()));
        assert!(messages.contains(&"Use `String(new Date())` instead of `Date()`.".to_string()));
        assert!(messages
            .contains(&"Use `new Intl.Collator()` instead of `Intl.Collator()`.".to_string()));
        assert!(messages
            .contains(&"Use `new Int8Array()` instead of `Int8Array()`.".to_string()));
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
        let messages = filtered(&report, "typescript:S7723");
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
