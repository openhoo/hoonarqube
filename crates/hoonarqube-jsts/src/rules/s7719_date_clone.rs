// Rule module s7719_date_clone (generated).
//
// `typescript:S7719` — Date objects should be cloned directly without calling
// "getTime()". Reference semantics: eslint-plugin-unicorn
// `consistent-date-clone` (wrapped by SonarJS S7719): a `new Date(...)`
// expression with exactly one argument that is a zero-argument `.getTime()`
// method call is an indirect clone. The finding is anchored on the
// `getTime()` portion, and the reference implementation is purely syntactic:
// overridden `getTime` members and non-Date receivers are reported the same
// way, and no auto-fix is offered (a replacement must be validated against
// the target library and runtime first).
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7719_flags_pinned_zod_date_clone_anchor() {
        // Pinned anchor: colinhacks/zod@46da957 packages/zod/src/v3/types.ts:1939
        // `value: new Date((input.data as Date).getTime()),`
        let source = "declare const input: { data: unknown };\n\
                      const value = new Date((input.data as Date).getTime());\n";
        let report = ts(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "typescript:S7719"), 1);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "typescript:S7719")
            .expect("pinned zod date clone must be reported");
        assert_eq!(issue.message, "Unnecessary `.getTime()` call.");
        assert_eq!(issue.range.start.line, 2);
        assert_eq!(
            issue.range.start.column,
            "const value = new Date((input.data as Date).".len() as u32
        );
        assert_eq!(issue.range.end.line, 2);
        assert_eq!(
            issue.range.end.column,
            "const value = new Date((input.data as Date).getTime());".len() as u32
        );
    }

    #[test]
    fn s7719_direct_clones_and_other_arguments_stay_silent() {
        let silent = "\
const direct = new Date(original);
const two_arguments = new Date(original.getTime(), 0);
const stamp = original.getTime();
const other_call = new Date(builder.now());
const optional = new Date(original?.getTime());
const plain_call = new Date(getTime());
";
        assert_eq!(count_key(&ts_keys(silent), "typescript:S7719"), 0);
    }

    #[test]
    fn s7719_flags_parenthesized_and_nested_receivers_like_reference() {
        let source = "\
const parenthesized = new Date((wrapped.getTime()));
const nested_member = new Date(boxed.value.getTime());
const indexed = new Date(list[0].getTime());
";
        assert_eq!(count_key(&ts_keys(source), "typescript:S7719"), 3);
    }

    #[test]
    fn s7719_overridden_gettime_flags_like_reference_without_quickfix() {
        // Acceptance control (openhoo/hoonarqube#185): the reference detector
        // is syntactic, so an overridden `getTime` member is reported the
        // same way and no quickfix may claim universal equivalence.
        let source = "\
class Tagged extends Date {
  override getTime(): number {
    return 0;
  }
}
const cloned = new Date(new Tagged().getTime());
";
        let report = ts(source);
        assert_eq!(count_key(&report_keys(&report), "typescript:S7719"), 1);
        assert!(
            report.issues.iter().all(|issue| issue.fix.is_none()),
            "S7719 must not offer an automatic fix"
        );
    }

    #[test]
    fn s7719_stays_silent_in_javascript_files() {
        let source = "const value = new Date(input.getTime());\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S7719"), 0);
    }
}
