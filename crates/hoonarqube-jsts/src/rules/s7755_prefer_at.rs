// Rule module s7755_prefer_at (generated).
//
// `javascript:S7755` + `typescript:S7755` — Complex index access patterns
// should be replaced with ".at()" method. Reference semantics:
// eslint-plugin-unicorn `prefer-at` at the version pinned by SonarJS 13.x
// (v65.0.1, wrapped by SonarJS S7755, default options
// `checkAllIndexAccess: false`, no extra `getLastElementFunctions`):
//
// - computed member access `foo[foo.length - N]` (a positive numeric literal
//   N, including nested `length - N - 1` chains that resolve to the same
//   receiver reference) is reported on the index expression with the
//   reference message "Prefer `.at(…)` over `[….length - index]`.";
// - `foo.charAt(foo.length - N)` is reported on the index argument with
//   "Prefer `String#at(…)` over `String#charAt(….length - index)`.";
// - first-element `.slice(-N)` reads — `slice(-1)[0]`, `slice(-1).shift()`,
//   `slice(-1).pop()`, and the wider `slice(-N, -N-1)`/suggested forms — are
//   reported on the `slice` property with "Prefer `.at(…)` over the first
//   element from `.slice(…)`.";
// - `_.last(x)`, `lodash.last(x)`, and `underscore.last(x)` are reported on
//   the callee with "Prefer `.at(-1)` over `_.last(…)` to get the last
//   element.".
//
// Assignment targets, the `arguments` object, positive-index access, and
// receivers with a different reference than the `length` receiver stay
// silent. Receiver element semantics and the ES2022 `.at()` target remain
// caller-qualified per the issue guard: no auto-fix is offered.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7755_flags_pinned_axios_to_form_data_anchor() {
        // Pinned anchor: axios/axios@18e7dfed lib/helpers/toFormData.js:173
        // `while (ancestors.length && ancestors[ancestors.length - 1] !== this) {`
        let source = "\
function walk(ancestors) {
  while (ancestors.length && ancestors[ancestors.length - 1] !== this) {
    ancestors.pop();
  }
}
";
        let report = js(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "javascript:S7755"), 1);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "javascript:S7755")
            .expect("pinned axios ancestors access must be reported");
        assert_eq!(issue.message, "Prefer `.at(…)` over `[….length - index]`.");
        assert_eq!(issue.range.start.line, 2);
        let prefix = "  while (ancestors.length && ancestors[";
        assert_eq!(
            issue.range.start.column,
            u32::try_from(prefix.len()).unwrap()
        );
        let index = "ancestors.length - 1";
        assert_eq!(
            issue.range.end.column,
            u32::try_from(prefix.len() + index.len()).unwrap()
        );
    }

    #[test]
    fn s7755_flags_pinned_markdown_it_table_anchor() {
        // Pinned anchor: markdown-it/markdown-it@3c51991 src/rules_block/table.ts:126+188
        // `if (columns.length && columns[columns.length - 1] === '') columns.pop()`
        let source = "\
function table() {
  if (columns.length && columns[columns.length - 1] === '') columns.pop();
  if (columns.length && columns[columns.length - 1] === '') columns.pop();
}
";
        let keys = ts_keys(source);
        assert_eq!(count_key(&keys, "typescript:S7755"), 2);
        let findings: Vec<u32> = ts_keys(source)
            .iter()
            .filter(|(key, _)| key == "typescript:S7755")
            .map(|(_, line)| *line)
            .collect();
        assert_eq!(findings, vec![3, 4]);
    }

    #[test]
    fn s7755_flags_all_reference_case_families() {
        let source = "\
const list = [];
const first = list[list.length - 1];
const second = list[list.length - 2];
const nested = list[list.length - 1 - 1];
const half = list[list.length - 1.5];
const char = 'abc'.charAt('abc'.length - 1);
const charAt = char.charAt(char.length - 2);
const sl = list.slice(-1)[0];
const sh = list.slice(-1).shift();
const pop = list.slice(-1).pop();
const two = list.slice(-2, -1)[0];
const lo = _.last(list);
const lo2 = lodash.last(list);
const lo3 = underscore.last(list);
";
        let report = js(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "javascript:S7755"), 13);
        let messages: Vec<&str> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S7755")
            .map(|issue| issue.message.as_str())
            .collect();
        assert_eq!(
            messages
                .iter()
                .filter(|message| **message == "Prefer `.at(…)` over `[….length - index]`.")
                .count(),
            4
        );
        assert_eq!(
            messages
                .iter()
                .filter(|message| {
                    **message == "Prefer `String#at(…)` over `String#charAt(….length - index)`."
                })
                .count(),
            2
        );
        assert_eq!(
            messages
                .iter()
                .filter(|message| {
                    **message == "Prefer `.at(…)` over the first element from `.slice(…)`."
                })
                .count(),
            4
        );
        assert!(messages.contains(&"Prefer `.at(-1)` over `_.last(…)` to get the last element."));
        assert!(
            messages.contains(&"Prefer `.at(-1)` over `lodash.last(…)` to get the last element.")
        );
        assert!(
            messages
                .contains(&"Prefer `.at(-1)` over `underscore.last(…)` to get the last element.")
        );
    }

    #[test]
    fn s7755_non_matching_forms_stay_silent() {
        let source = "\
const list = [];
const zero = list[0];
const bareLength = list[list.length];
const other = list[missing.length - 1];
list[list.length - 1] = 1;
function args() {
  return arguments[arguments.length - 1];
}
const bareSlice = list.slice(-1);
const deepSlice = list.slice(-2);
const positiveSlice = list.slice(1)[0];
const weirdRange = list.slice(-1, -2)[0];
const farEnd = list.slice(-2)[0];
const notFirst = list.slice(-1)[1];
const bareLast = last(list);
const extraLast = _.last(list, 2);
const firstOf = _.first(list);
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7755"), 0);
    }

    #[test]
    fn s7755_reports_in_both_languages() {
        let ts_source = "\
declare const list: string[];
const first = list[list.length - 1];
";
        let js_source = "\
const list = [];
const first = list[list.length - 1];
";
        assert_eq!(count_key(&js_keys(js_source), "javascript:S7755"), 1);
        assert_eq!(count_key(&ts_keys(ts_source), "typescript:S7755"), 1);
    }
}
