// Rule module s7754_prefer_array_some (generated).
//
// `javascript:S7754` + `typescript:S7754` — Use ".some()" instead of
// ".filter().length" checks or ".find()" for existence testing. Reference
// semantics: eslint-plugin-unicorn `prefer-array-some` at the version pinned
// by SonarJS 13.x (v65.0.1, wrapped by SonarJS S7754):
//
// - `.find(cb)`/`.findLast(cb)` (1-2 arguments, non-optional call and member,
//   no explicit type arguments) whose result is immediately booleanized:
//   `!!`, `!`, `Boolean(...)`, a `&&`/`||` chain used as a boolean or a
//   control-flow test, or a comparison with `undefined` (`===`, `!==`, `==`,
//   `!=`) or a loose comparison with `null`, always with the call on the
//   left of the comparison;
// - a `const`-declared single identifier initialized by such a `.find()`
//   call, without a type annotation and not directly exported, whose reads
//   are all boolean expressions or control-flow tests;
// - `.findIndex(cb)`/`.findLastIndex(cb)` compared against `-1` (`!==`, `!=`,
//   `>`, `===`, `==`) or `0` (`>=`, `<`);
// - `.filter(cb).length > 0` and `.filter(cb).length !== 0`, with a
//   non-function first `.filter()` argument and `$`-prefixed receivers kept
//   silent.
//
// Each report is anchored on the method property, with the reference message
// "Prefer `.some(…)` over `.{method}(…)`." and, for the filter-length form,
// "Prefer `.some(…)` over non-zero length check from `.filter(…)`.". Find
// results consumed as values (returned, stored, indexed) stay silent. No
// auto-fix is offered: the reference suggestion rewrites the callback
// position only, and found-element substitution is rejected per the issue
// guard.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7754_flags_pinned_zod_types_anchor() {
        // Pinned anchor: colinhacks/zod@46da957 packages/zod/src/v3/types.ts:1253
        // `return !!this._def.checks.find((ch) => ch.kind === "datetime");`
        // (same file also carries the line 1257 and 1261 occurrences).
        let source = "\
class Check {
  isDatetime(): boolean {
    return !!this._def.checks.find((ch) => ch.kind === \"datetime\");
  }

  isDate(): boolean {
    return !!this._def.checks.find((ch) => ch.kind === \"date\");
  }

  isTime(): boolean {
    return !!this._def.checks.find((ch) => ch.kind === \"time\");
  }
}
";
        let report = ts(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "typescript:S7754"), 3);
        let mut issues: Vec<(u32, u32, &str)> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "typescript:S7754")
            .map(|issue| {
                (
                    issue.range.start.line,
                    issue.range.start.column,
                    issue.message.as_str(),
                )
            })
            .collect();
        issues.sort();
        let prefix = "    return !!this._def.checks.";
        assert_eq!(
            issues,
            vec![
                (
                    3,
                    u32::try_from(prefix.len()).unwrap(),
                    "Prefer `.some(…)` over `.find(…)`."
                ),
                (
                    6,
                    u32::try_from(prefix.len()).unwrap(),
                    "Prefer `.some(…)` over `.find(…)`."
                ),
                (
                    9,
                    u32::try_from(prefix.len()).unwrap(),
                    "Prefer `.some(…)` over `.find(…)`."
                ),
            ]
        );
    }

    #[test]
    fn s7754_flags_all_reference_case_families() {
        let source = "\
const list = [];
const a = !!list.find((x) => x.ok);
const b = Boolean(list.find((x) => x.ok));
const c = !list.findLast((x) => x.ok);
if (list.find((x) => x.ok)) { }
while (list.find((x) => x.ok)) { break; }
const d = list.find((x) => x.ok) !== undefined;
const e = list.find((x) => x.ok) == null;
const f = list.findIndex((x) => x) !== -1;
const g = list.findIndex((x) => x) >= 0;
const h = list.findLastIndex((x) => x) === -1;
const i = list.findIndex((x) => x) > -1;
const j = list.findIndex((x) => x) < 0;
const k = list.filter((x) => x.ok).length > 0;
const l = list.filter((x) => x.ok).length !== 0;
";
        let report = js(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "javascript:S7754"), 14);
        let messages: Vec<&str> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S7754")
            .map(|issue| issue.message.as_str())
            .collect();
        assert!(messages.contains(&"Prefer `.some(…)` over `.find(…)`."));
        assert!(messages.contains(&"Prefer `.some(…)` over `.findLast(…)`."));
        assert!(messages.contains(&"Prefer `.some(…)` over `.findIndex(…)`."));
        assert!(messages.contains(&"Prefer `.some(…)` over `.findLastIndex(…)`."));
        assert!(
            messages.contains(&"Prefer `.some(…)` over non-zero length check from `.filter(…)`.")
        );
    }

    #[test]
    fn s7754_flags_const_find_result_used_only_as_boolean() {
        let source = "\
function run(list) {
  const found = list.find((x) => x.ok);
  if (found) { return true; }
  return !found;
}
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S7754"), 1);
    }

    #[test]
    fn s7754_find_results_consumed_as_values_stay_silent() {
        let source = "\
function run(list) {
  const first = list.find((x) => x.ok);
  return first[0];
}
function chain(list) {
  return list.find((x) => x.ok).toString();
}
function passed(list) {
  return list.find((x) => x.ok, { threshold: 1 });
}
function leaked(list) {
  const bare = list.find((x) => x.ok);
  return bare;
}
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7754"), 0);
    }

    #[test]
    fn s7754_reference_guards_stay_silent() {
        let source = "\
export const exported = list.find((x) => x.ok);
if (exported) { }
function run(list) {
  if (list?.find((x) => x.ok)) { return true; }
  if (list.find?.((x) => x.ok)) { return true; }
  if (list.find()) { return true; }
  const yoda = undefined !== list.find((x) => x.ok);
  const positive = list.findIndex((x) => x) === 0;
  const greater = list.findIndex((x) => x) > 0;
  const dollar = $.filter((x) => x.ok).length > 0;
  const noCallback = list.filter().length > 0;
  const notFunction = list.filter(1).length > 0;
  const separate = list.filter((x) => x.ok).length;
  if (separate > 0) { return true; }
  return false;
}
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7754"), 0);
    }

    #[test]
    fn s7754_type_arguments_stay_silent() {
        let source = "\
function run<T>(list: T[]) {
  if (list.find<T>((x) => !!x)) { return true; }
  return false;
}
";
        assert_eq!(count_key(&ts_keys(source), "typescript:S7754"), 0);
    }

    #[test]
    fn s7754_reports_in_both_languages() {
        let ts_source = "\
declare const list: { ok: boolean }[];
const a = !!list.find((x) => x.ok);
";
        let js_source = "\
const list = [];
const a = !!list.find((x) => x.ok);
";
        assert_eq!(count_key(&js_keys(js_source), "javascript:S7754"), 1);
        assert_eq!(count_key(&ts_keys(ts_source), "typescript:S7754"), 1);
    }
}
