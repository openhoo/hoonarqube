// Rule module s7726_named_default_export (generated).
//
// `javascript:S7726` / `typescript:S7726` — Default exports should be
// named. Reference semantics: eslint-plugin-unicorn
// `no-anonymous-default-export`: an anonymous function, async function,
// generator function, async generator function, or class in a default
// export is reported with "The <description> should be named.", including
// parenthesized function and class expressions, and the CommonJS forms
// `module.exports = <anonymous>` and `exports = <anonymous>`. Named
// declarations, aliases of existing bindings, and non-function defaults
// (literals, object and array literals) stay silent. Findings span the
// anonymous declaration.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7726_flags_pinned_anonymous_arrow_anchor_in_axios() {
        // Pinned anchor: axios@18e7dfed lib/helpers/parseHeaders.js:41
        // `export default (rawHeaders) => {`
        let source = "export default (rawHeaders) => {\n\
                      const parsed = {};\n\
                      return parsed;\n\
                      };\n";
        let report = js(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "javascript:S7726"), 1);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "javascript:S7726")
            .expect("the pinned axios anonymous default arrow must be reported");
        assert_eq!(issue.message, "The arrow function should be named.");
        assert_eq!(issue.range.start.line, 1);
        assert_eq!(issue.range.start.column, "export default ".len() as u32);
    }

    #[test]
    fn s7726_flags_pinned_zod_locale_anchor_in_typescript() {
        // Pinned anchor: colinhacks/zod@46da957
        // packages/zod/src/v4/locales/ar.ts:115, representative of all 63
        // locale modules exporting an anonymous default function.
        let source = "export default function (): { localeError: string } {\n\
                      return { localeError: '' };\n\
                      }\n";
        let report = ts(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "typescript:S7726"), 1);
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "typescript:S7726")
            .expect("the pinned zod locale default function must be reported");
        assert_eq!(issue.message, "The function should be named.");
        assert_eq!(issue.range.start.line, 1);
        assert_eq!(issue.range.start.column, "export default ".len() as u32);
    }

    #[test]
    fn s7726_flags_anonymous_function_class_and_commonjs_forms() {
        let source = "\
export default function () {}
export default async function () {}
export default function* () {}
export default async function* () {}
export default class {}
export default (function () {});
module.exports = function () {};
exports = () => ({});
";
        let report = js(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "javascript:S7726"), 8);
        let messages = filtered(&report, "javascript:S7726");
        assert!(messages.contains(&"The async function should be named.".to_string()));
        assert!(messages.contains(&"The generator function should be named.".to_string()));
        assert!(messages.contains(&"The async generator function should be named.".to_string()));
        assert!(messages.contains(&"The class should be named.".to_string()));
    }

    #[test]
    fn s7726_named_exports_and_non_function_defaults_stay_silent() {
        let silent = "\
export default function parseHeaders(rawHeaders) {}
export default class HeaderParser {}
export default 42;
export default { parse };
export default [];
const impl = () => ({});
export default impl;
export default (function named() {});
module.exports = { parse: parseHeaders };
";
        assert_eq!(count_key(&js_keys(silent), "javascript:S7726"), 0);
    }

    #[test]
    fn s7726_flags_both_javascript_and_typescript_files() {
        let source = "export default () => ({});\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S7726"), 1);
        assert_eq!(count_key(&ts_keys(source), "typescript:S7726"), 1);
    }
}
