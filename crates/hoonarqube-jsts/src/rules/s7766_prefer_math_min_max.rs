// Rule module s7766_prefer_math_min_max (generated).
//
// `javascript:S7766` + `typescript:S7766` — Ternary expressions should be
// replaced with "Math.min()" or "Math.max()" for simple comparisons.
// Reference semantics: eslint-plugin-unicorn `prefer-math-min-max` at the
// version pinned by SonarJS 13.x (v65.0.1, wrapped by SonarJS S7766):
// a conditional expression whose test is a `<`, `<=`, `>`, or `>=`
// comparison and whose branches repeat the comparison operands
// textually (`a > b ? a : b` -> `Math.max(a, b)`, `a > b ? b : a` ->
// `Math.min(a, b)`, and the mirrored `<`/`<=` forms) is reported on the
// whole conditional expression with the reference message
// "Prefer `Math.{min,max}()` to simplify ternary expressions.".
//
// Guards from the reference implementation: BigInt literals and `BigInt(...)`
// operands stay silent, `new Date` operands stay silent, TS-unwrapped
// operands (`as`/`satisfies`/non-null) must carry number type annotations,
// and identifiers declared with a non-number type annotation, with a
// non-number literal initializer, or initialized with `new Date` stay
// silent. NaN and signed-zero propagation therefore remain caller-visible
// per the issue guard: only provably textual operand repetition is
// reported, and no auto-fix is offered.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7766_flags_pinned_zod_dec_count_anchor() {
        // Pinned anchor: colinhacks/zod@46da957 packages/zod/src/v3/types.ts:1357
        // `const decCount = valDecCount > stepDecCount ? valDecCount : stepDecCount;`
        let source = "\
function decCounts(valDecCount: number, stepDecCount: number) {
  const decCount = valDecCount > stepDecCount ? valDecCount : stepDecCount;
  return decCount;
}
";
        let report = ts(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "typescript:S7766"), 1);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "typescript:S7766")
            .expect("pinned zod decCount ternary must be reported");
        assert_eq!(
            issue.message,
            "Prefer `Math.max()` to simplify ternary expressions."
        );
        assert_eq!(issue.range.start.line, 2);
        let prefix = "  const decCount = ";
        assert_eq!(
            issue.range.start.column,
            u32::try_from(prefix.len()).unwrap()
        );
        let ternary = "valDecCount > stepDecCount ? valDecCount : stepDecCount";
        assert_eq!(
            issue.range.end.column,
            u32::try_from(prefix.len() + ternary.len()).unwrap()
        );
    }

    #[test]
    fn s7766_flags_reference_min_and_max_families() {
        let source = "\
const min1 = height > 50 ? 50 : height;
const min2 = height < 50 ? height : 50;
const max1 = height >= 50 ? height : 50;
const max2 = height <= 50 ? 50 : height;
";
        let report = js(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "javascript:S7766"), 4);
        let messages: Vec<&str> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S7766")
            .map(|issue| issue.message.as_str())
            .collect();
        assert_eq!(
            messages
                .iter()
                .filter(
                    |message| **message == "Prefer `Math.min()` to simplify ternary expressions."
                )
                .count(),
            2
        );
        assert_eq!(
            messages
                .iter()
                .filter(
                    |message| **message == "Prefer `Math.max()` to simplify ternary expressions."
                )
                .count(),
            2
        );
    }

    #[test]
    fn s7766_flags_literal_operand_text_repetition() {
        let source = "\
const smaller = 'a' > 'b' ? 'b' : 'a';
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7766"), 1);
    }

    #[test]
    fn s7766_non_equivalent_ternaries_stay_silent() {
        let source = "\
const wrong = alpha > beta ? alpha : gamma;
const nonTest = flag ? alpha : beta;
const equality = alpha == beta ? alpha : beta;
const inequality = alpha != beta ? alpha : beta;
const swapped = alpha > beta ? beta : gamma;
const big = 10n > 5n ? 10n : 5n;
const dates = new Date(alpha) > new Date(beta) ? alpha : beta;
var sa = 'x';
var sb = 'y';
const literals = sa > sb ? sa : sb;
function typed(a: string, b: string) {
  return a > b ? a : b;
}
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7766"), 0);
        assert_eq!(count_key(&ts_keys(source), "typescript:S7766"), 0);
    }

    #[test]
    fn s7766_reports_in_both_languages() {
        let ts_source = "\
declare const height: number;
const m = height > 50 ? 50 : height;
";
        let js_source = "\
const height = readHeight();
const m = height > 50 ? 50 : height;
";
        assert_eq!(count_key(&js_keys(js_source), "javascript:S7766"), 1);
        assert_eq!(count_key(&ts_keys(ts_source), "typescript:S7766"), 1);
    }
}
