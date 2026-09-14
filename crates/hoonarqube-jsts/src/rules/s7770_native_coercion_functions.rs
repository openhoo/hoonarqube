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
        assert!(
            messages.contains(&"arrow function is equivalent to `Number`. Use `Number` directly.")
        );
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
