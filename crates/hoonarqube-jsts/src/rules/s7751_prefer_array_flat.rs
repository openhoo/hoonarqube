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
const chained = [].concat(array).concat(array);
const own = array.concat(array);
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
        let source = "\
declare const array: number[][];
const first = [].concat(array);
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7751"), 1);
        assert_eq!(count_key(&ts_keys(source), "typescript:S7751"), 1);
    }
}
