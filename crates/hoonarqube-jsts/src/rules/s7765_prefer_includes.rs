// Rule module s7765_prefer_includes (generated).
//
// `javascript:S7765` + `typescript:S7765` — Existence checks should use
// ".includes()" instead of ".indexOf()" or ".lastIndexOf()". Reference
// semantics: eslint-plugin-unicorn `prefer-includes` at the version pinned
// by SonarJS 13.x (v65.0.1, wrapped by SonarJS S7765):
//
// - `x.indexOf(v)`/`x.lastIndexOf(v)` (non-optional member and call) on the
//   left of a comparison whose right side is `-1` with `!==`, `!=`, `>`,
//   `===`, or `==`, or `0` with `>=` or `<`, is reported on the method
//   property with "Use `.includes()`, rather than `.{method}()`, when
//   checking for existence.". Receivers named `_`, `lodash`, or
//   `underscore` stay silent, more than two arguments stay silent, and a
//   literal `0` `fromIndex` is still reported;
// - `.some(cb)` whose single-parameter non-async callback body is exactly
//   `param === value` (expression or single `return`) is reported on the
//   `some` property with "Use `.includes()` instead of `.some()` when
//   checking value existence.", unless the parameter is referenced outside
//   the comparison or the named callback recurses into itself.
//
// Index-value uses, coercion polarity, and non-comparison forms stay silent
// per the issue guard; no auto-fix is offered.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7765_flags_pinned_axios_anchors() {
        // Pinned anchors: axios/axios@18e7dfed lib/core/dispatchRequest.js:48,
        // lib/defaults/index.js:47 and :82.
        let source = "\
function dispatch(config, contentType) {
  if (['post', 'put', 'patch'].indexOf(config.method) !== -1) {
    return 'data';
  }
  const hasJSONContentType = contentType.indexOf('application/json') > -1;
  if (contentType.indexOf('application/x-www-form-urlencoded') > -1) {
    return 'form';
  }
  return hasJSONContentType;
}
";
        let report = js(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "javascript:S7765"), 3);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "javascript:S7765")
            .expect("pinned axios indexOf existence check must be reported");
        assert_eq!(
            issue.message,
            "Use `.includes()`, rather than `.indexOf()`, when checking for existence."
        );
        assert_eq!(issue.range.start.line, 2);
        let prefix = "  if (['post', 'put', 'patch'].";
        assert_eq!(
            issue.range.start.column,
            u32::try_from(prefix.len()).unwrap()
        );
        assert_eq!(
            issue.range.end.column,
            u32::try_from(prefix.len() + "indexOf".len()).unwrap()
        );
        let lines: Vec<u32> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S7765")
            .map(|issue| issue.range.start.line)
            .collect();
        assert_eq!(lines, vec![2, 5, 6]);
    }

    #[test]
    fn s7765_flags_pinned_zod_and_markdown_it_anchors() {
        // Pinned anchors: colinhacks/zod@46da957 packages/zod/src/v3/types.ts:3249
        // (`bKeys.indexOf(key) !== -1`) and v4/core/util.ts:279
        // (`numericValues.indexOf(+k) === -1`); markdown-it@3c51991 src/ruler.ts:71,
        // src/rules_block/fence.ts:32 (`>= 0`), src/rules_block/table.ts:122
        // (`=== -1`).
        let zod_v3 = "\
function sharedKeys(aKeys, bKeys) {
  return Object.keys(aKeys).filter((key) => bKeys.indexOf(key) !== -1);
}
";
        assert_eq!(count_key(&ts_keys(zod_v3), "typescript:S7765"), 1);

        let javascript = "\
function numericEntries(entries, values) {
  return entries.filter(([k, v]) => values.indexOf(+k) === -1);
}
function rulerChecks(rule, chain, params, marker, lineText) {
  if (rule.enabled && rule.alt.indexOf(chain) >= 0) return true;
  if (params.indexOf(String.fromCharCode(marker)) >= 0) return true;
  if (lineText.indexOf('|') === -1) return false;
  return false;
}
";
        assert_eq!(count_key(&js_keys(javascript), "javascript:S7765"), 4);
    }

    #[test]
    fn s7765_flags_reference_operator_and_method_families() {
        let source = "\
const list = [];
const a = list.lastIndexOf(item) !== -1;
const b = list.indexOf(item, 2) !== -1;
const c = list.indexOf(item, 0) !== -1;
const d = list.lastIndexOf(item) == -1;
const e = list.indexOf(item) < 0;
";
        let report = js(source);
        let messages: Vec<&str> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S7765")
            .map(|issue| issue.message.as_str())
            .collect();
        assert_eq!(messages.len(), 5);
        assert!(messages.contains(
            &"Use `.includes()`, rather than `.lastIndexOf()`, when checking for existence."
        ));
        assert_eq!(
            messages
                .iter()
                .filter(|message| {
                    **message
                        == "Use `.includes()`, rather than `.indexOf()`, when checking for existence."
                })
                .count(),
            3
        );
    }

    #[test]
    fn s7765_non_existence_forms_stay_silent() {
        let source = "\
const list = [];
const f = _.indexOf(list, item) !== -1;
const g = lodash.indexOf(list, item) !== -1;
const h = underscore.indexOf(list, item) !== -1;
const i = list?.indexOf(item) !== -1;
const j = -1 !== list.indexOf(item);
const k = list.indexOf(item) > 0;
const l = list.indexOf(item) === 0;
const m = list.indexOf(item, 0, 1) !== -1;
const position = list.indexOf(item);
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7765"), 0);
    }

    #[test]
    fn s7765_flags_some_value_existence_wrappers() {
        let source = "\
const has = list.some((item) => item === target);
const block = list.some((item) => { return item === target; });
";
        let report = js(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "javascript:S7765"), 2);
        let messages: Vec<&str> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S7765")
            .map(|issue| issue.message.as_str())
            .collect();
        assert!(
            messages
                .contains(&"Use `.includes()` instead of `.some()` when checking value existence.")
        );
    }

    #[test]
    fn s7765_non_simple_some_callbacks_stay_silent() {
        let source = "\
const neg = list.some((item) => item !== target);
const multi = list.some((item) => item === target && item !== other);
const asyncCb = list.some(async (item) => item === target);
const twoParams = list.some((item, index) => item === target);
const reused = list.some((item) => item === String(item));
const selfRef = list.some(function self(item) { return item === self(); });
const spread = list.some(...callbacks);
const generator = list.some(function* (item) { return item === target; });
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7765"), 0);
    }

    #[test]
    fn s7765_reports_in_both_languages() {
        let ts_source = "\
declare const list: string[];
const a = list.indexOf(item) !== -1;
";
        let js_source = "\
const list = [];
const a = list.indexOf(item) !== -1;
";
        assert_eq!(count_key(&js_keys(js_source), "javascript:S7765"), 1);
        assert_eq!(count_key(&ts_keys(ts_source), "typescript:S7765"), 1);
    }
}
