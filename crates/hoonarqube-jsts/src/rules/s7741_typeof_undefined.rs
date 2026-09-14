// Rule module s7741_typeof_undefined (generated).
//
// `javascript:S7741` + `typescript:S7741` — "typeof" should not be used to
// check for "undefined". Reference semantics: eslint-plugin-unicorn
// `no-typeof-undefined` at the version pinned by SonarJS 13.x (v65.0.1,
// wrapped by SonarJS S7741, default options): a `typeof x` operand compared
// with the string literal `'undefined'` using `===`, `!==`, `==`, or `!=`
// is reported on the `typeof` keyword. Operands that are plain identifiers
// resolving to a global scope binding or to no binding at all (undeclared
// runtime globals such as `window` or `Promise`) are legitimate
// `typeof` guards and stay silent; member, element, and optional-chain
// operands are reported. No auto-fix is offered.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7741_flags_pinned_markdownit_parser_inline_anchor() {
        // Pinned anchor: markdown-it/markdown-it@3c51991 src/parser_inline.ts:97
        // `if (typeof cache[pos] !== 'undefined') {`
        let source = "\
export function cached(cache: unknown[], pos: number): boolean {
  if (typeof cache[pos] !== 'undefined') {
    return true;
  }
  return false;
}
";
        let report = ts(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "typescript:S7741"), 1);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "typescript:S7741")
            .expect("pinned markdown-it typeof guard must be reported");
        assert_eq!(
            issue.message,
            "Compare with `undefined` directly instead of using `typeof`."
        );
        assert_eq!(issue.range.start.line, 2);
        assert_eq!(
            issue.range.start.column,
            u32::try_from("  if (".len()).unwrap()
        );
        assert_eq!(issue.range.end.line, 2);
        assert_eq!(
            issue.range.end.column,
            u32::try_from("  if (typeof".len()).unwrap()
        );
    }

    #[test]
    fn s7741_flags_all_seven_markdownit_occurrences() {
        // The seven successful reference findings in the pinned markdown-it
        // scan: parser_inline.ts:97, renderer.ts:276 and :333,
        // rules_block/reference.ts:204 and :207, rules_inline/image.ts:84,
        // and rules_inline/link.ts:88 (rules[type] appears twice).
        let source = "\
const cache: unknown[] = [];
const pos = 0;
const rules: Record<string, unknown> = {};
const type = \"a\";
const state = { env: { references: {} as Record<string, unknown> } };
const label = \"x\";
if (typeof cache[pos] !== 'undefined') {}
if (typeof rules[type] !== 'undefined') {}
if (typeof rules[type] !== 'undefined') {}
if (typeof state.env.references === 'undefined') {}
if (typeof state.env.references[label] === 'undefined') {}
if (typeof state.env.references === 'undefined') {}
if (typeof state.env.references === 'undefined') {}
";
        assert_eq!(count_key(&ts_keys(source), "typescript:S7741"), 7);
    }

    #[test]
    fn s7741_flags_five_comparable_zod_shapes() {
        // The five comparable pinned zod findings: parseUtil.ts:144,
        // types.ts:136, types.ts:336, types.ts:1130, and types.ts:1158.
        let source = "\
const value = { value: 1 as unknown };
const ctx = { data: 1 as unknown };
let message: string | undefined;
const options = {} as { precision?: number } | undefined;
if (typeof value.value !== \"undefined\") {}
if (typeof ctx.data === \"undefined\") {}
if (typeof message === \"undefined\") {}
if (typeof options?.precision === \"undefined\") {}
if (typeof options?.precision === \"undefined\") {}
";
        assert_eq!(count_key(&ts_keys(source), "typescript:S7741"), 5);
    }

    #[test]
    fn s7741_global_guards_stay_silent() {
        // Pinned silent zod guards: parseUtil.ts:176, helpers/util.ts:210-216,
        // types.ts:351, v4/core/util.ts:524,611,614,617,621 — plus the
        // undeclared `window`/`File` runtime globals that must keep their
        // legitimate `typeof` form.
        let silent = "\
if (typeof Promise !== 'undefined') {}
if (typeof Map !== 'undefined') {}
if (typeof Set !== 'undefined') {}
if (typeof Date !== 'undefined') {}
if (typeof navigator !== 'undefined') {}
if (typeof window !== 'undefined') {}
if (typeof File !== 'undefined') {}
";
        assert_eq!(count_key(&ts_keys(silent), "typescript:S7741"), 0);
    }

    #[test]
    fn s7741_non_comparisons_stay_silent() {
        let silent = "\
declare const value: unknown;
const kind = typeof value;
if (kind === 'undefined') {}
if (typeof value === 'string') {}
const direct = value === undefined;
const negated = typeof value;
";
        assert_eq!(count_key(&ts_keys(silent), "typescript:S7741"), 0);
    }

    #[test]
    fn s7741_reports_in_both_languages() {
        let source = "if (typeof cache[pos] !== 'undefined') {}\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S7741"), 1);
        assert_eq!(count_key(&js_keys(source), "typescript:S7741"), 0);
    }
}
