// Rule module s7776_prefer_set_has (generated).
//
// `javascript:S7776` + `typescript:S7776` — Arrays used only for existence
// checks should be Sets. Reference semantics: eslint-plugin-unicorn
// `prefer-set-has` at the version pinned by SonarJS 13.x (v65.0.1, wrapped
// by SonarJS S7776).
//
// A non-exported `const` declarator initialized with an array-shaped
// expression (array literal, `Array()`/`new Array()`, `Array.from()`/
// `Array.of()`, the array-returning method list, or `slice`/`concat` on a
// non-string receiver) is reported when every remaining reference is an
// existence check (`includes(...)` with one argument), a `length` read, or
// one of the Set-compatible extra uses (`for-of` iteration, argument/array
// spread, single-callback `forEach`). Extras additionally require a known
// unique literal array; a single `includes` use must be called repeatedly
// (inside a loop or function between the call and the declaration).
// Reassignment, indexing, mutation, optional access, and exported identity
// stay silent. The report anchors on the declarator identifier with the
// reference message "`NAME` should be a `Set`, and use `NAME.has()` to
// check existence or non-existence." No auto-fix is offered.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope};
use hoonarqube_ir::Issue;

/// Entry point: `javascript:S7776` + `typescript:S7776`
/// prefer-set-has check over the parsed program.
pub(crate) fn check(_ctx: &AnalysisContext) -> Vec<Issue> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7776_flags_pinned_axios_form_data_anchor() {
        // Pinned anchor: axios/axios@18e7dfe
        // lib/core/setFormDataHeaders.js:3 — Sonar: `FORM_DATA_CONTENT_HEADERS`
        // should be a `Set`, and use `FORM_DATA_CONTENT_HEADERS.has()` ...
        let source = "\
'use strict';

const FORM_DATA_CONTENT_HEADERS = ['content-type', 'content-length'];

export default function setFormDataHeaders(headers, formHeaders, policy) {
  if (policy !== 'content-only') {
    headers.set(formHeaders);
    return;
  }

  Object.entries(formHeaders || {}).forEach(([key, val]) => {
    if (FORM_DATA_CONTENT_HEADERS.includes(key.toLowerCase())) {
      headers.set(key, val);
    }
  });
}
";
        let report = js(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "javascript:S7776"), 1);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "javascript:S7776")
            .expect("pinned axios existence array must be reported");
        assert_eq!(
            issue.message,
            "`FORM_DATA_CONTENT_HEADERS` should be a `Set`, and use \
             `FORM_DATA_CONTENT_HEADERS.has()` to check existence or non-existence."
        );
        assert_eq!(issue.range.start.line, 3);
        assert_eq!(issue.range.start.column, u32::try_from("const ".len()).unwrap());
    }

    #[test]
    fn s7776_flags_repeated_includes_uses() {
        let source = "\
const MODES = ['a', 'b'];
const both = MODES.includes('a') || MODES.includes('b');
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S7776"), 1);
        assert!(keys.contains(&("javascript:S7776".to_string(), 1)));
    }

    #[test]
    fn s7776_flags_single_looped_include_with_length_reads() {
        let source = "\
const ITEMS = ['a', 'b'];
function total() {
  if (ITEMS.length > 0 && ITEMS.includes('a')) {
    return ITEMS.length;
  }
  return 0;
}
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7776"), 1);
    }

    #[test]
    fn s7776_flags_for_of_iteration_with_unique_literals() {
        let source = "\
const ROLES = ['admin', 'user'];
for (const role of ROLES) {
  if (ROLES.includes(role)) {
    grant(role);
  }
}
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7776"), 1);
    }

    #[test]
    fn s7776_flags_array_shaped_initializers() {
        let source = "\
const fromCtor = Array(3);
const a1 = fromCtor.includes(1) || fromCtor.includes(2);
const mapped = ['x'].map((value) => value);
const m1 = mapped.includes('x') || mapped.includes('y');
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S7776"), 2);
    }

    #[test]
    fn s7776_controls_stay_silent() {
        let source = "\
let mutable = ['a'];
const once = ['x'];
if (once.includes('x')) {
  hit();
}
const pushed = ['a'];
if (pushed.includes('a') || pushed.includes('b')) {
  pushed.push('c');
}
export const exported = ['a', 'b'];
const e1 = exported.includes('a');
const e2 = exported.includes('b');
const indexed = ['a', 'b'];
const first = indexed.includes('a') && indexed[0] === 'a';
const optionalChained = ['a'];
const o1 = optionalChained.includes('a') || optionalChained?.includes('b');
const dupExtra = ['a', 'a'];
for (const item of dupExtra) {
  if (dupExtra.includes(item)) {
    hit();
  }
}
const reassigned = ['a'];
reassigned = ['b'];
if (reassigned.includes('a')) {
  hit();
}
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7776"), 0);
    }

    #[test]
    fn s7776_reports_in_both_languages() {
        let js_source = "\
const MODES = ['a', 'b'];
const both = MODES.includes('a') || MODES.includes('b');
";
        let ts_source = "\
const roles: string[] = ['admin', 'user'];
function has(role: string) {
  return roles.includes(role) || roles.length > 0;
}
";
        assert_eq!(count_key(&js_keys(js_source), "javascript:S7776"), 1);
        assert_eq!(count_key(&ts_keys(ts_source), "typescript:S7776"), 1);
    }
}
