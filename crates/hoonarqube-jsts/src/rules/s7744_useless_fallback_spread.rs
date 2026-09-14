// Rule module s7744_useless_fallback_spread (generated).
//
// `javascript:S7744` + `typescript:S7744` — Unnecessary fallback objects
// should not be used when spreading in object literals. Reference
// semantics: eslint-plugin-unicorn `no-useless-fallback-in-spread` at the
// version pinned by SonarJS 13.x (v65.0.1, wrapped by SonarJS S7744): an
// empty object literal `{}` used as the right-hand side of a `||`/`??`
// logical expression whose whole result is spread into an object literal
// (`{ ...(value ?? {}) }`) is reported on the empty object. Property-value
// fallbacks and array spreads keep their necessary fallbacks and stay
// silent. No auto-fix is offered (comments and parenthesization around the
// fallback make the reference fix unsafe).
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7744_flags_pinned_zod_registries_anchor() {
        // Pinned anchor: colinhacks/zod@46da957
        // packages/zod/src/v4/core/registries.ts:66
        // `const pm: any = { ...(this.get(p) ?? {}) };`
        let source = "\
declare const registry: { get(p: string): Record<string, unknown> | undefined };
declare const p: string;
if (p) {
  const pm = { ...(registry.get(p) ?? {}) };
  delete pm.id;
}
";
        let report = ts(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "typescript:S7744"), 1);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "typescript:S7744")
            .expect("pinned registries spread fallback must be reported");
        assert_eq!(issue.message, "The empty object is useless.");
        assert_eq!(issue.range.start.line, 4);
        assert_eq!(
            issue.range.start.column,
            u32::try_from("  const pm = { ...(registry.get(p) ?? ".len()).unwrap()
        );
        assert_eq!(issue.range.end.line, 4);
        assert_eq!(
            issue.range.end.column,
            u32::try_from("  const pm = { ...(registry.get(p) ?? {}".len()).unwrap()
        );
    }

    #[test]
    fn s7744_flags_pinned_zod_to_json_schema_anchor() {
        // Pinned anchor: colinhacks/zod@46da957
        // packages/zod/src/v4/core/to-json-schema.ts:853
        // `initializeContext({ ...(libraryOptions ?? {}), target, io, processors })`
        let source = "\
declare const libraryOptions: Record<string, unknown> | undefined;
declare const target: string;
declare const io: string;
declare const processors: Record<string, unknown>;
declare function initializeContext(options: Record<string, unknown>): unknown;
const context = initializeContext({ ...(libraryOptions ?? {}), target, io, processors });
";
        let report = ts(source);
        assert_eq!(count_key(&report_keys(&report), "typescript:S7744"), 1);
    }

    #[test]
    fn s7744_property_fallbacks_and_array_spreads_stay_silent() {
        let silent = "\
declare const params: { processors?: Record<string, unknown> };
declare const external: { defs?: Record<string, unknown> } | undefined;
declare const arr: string[] | undefined;
const config = { processors: params.processors ?? {} };
const defs = external?.defs ?? {};
const spread = [...(arr ?? [])];
const logical = params.processors || {};
function direct(arg = {}) {
  return arg;
}
";
        assert_eq!(count_key(&ts_keys(silent), "typescript:S7744"), 0);
    }

    #[test]
    fn s7744_reports_in_both_languages() {
        let ts_source = "\
declare const source: Record<string, unknown> | undefined;
const merged = { ...(source ?? {}) };
";
        let js_source = "\
const source = read();
const merged = { ...(source ?? {}) };
";
        assert_eq!(count_key(&js_keys(js_source), "javascript:S7744"), 1);
        assert_eq!(count_key(&ts_keys(ts_source), "typescript:S7744"), 1);
    }
}
