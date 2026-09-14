// Rule module s7780_prefer_string_raw (generated).
//
// `javascript:S7780` + `typescript:S7780` — String literals with escaped
// backslashes should use `String.raw` template literals. Reference
// semantics: eslint-plugin-unicorn `prefer-string-raw` at the version
// pinned by SonarJS 13.x (v65.0.1, wrapped by SonarJS S7780).
//
// Two reference directions are implemented:
//
// - a single-line string literal whose only escapes are the doubled
//   backslash (and the escaped quote character) is reported so
//   `String.raw` can carry the text verbatim;
// - an untagged template literal whose quasis differ from their raw text
//   only by escaped backslashes is reported as well.
//
// Literals are silent in restricted positions (directives, non-computed
// property/method keys, module sources and specifiers, import attributes,
// JSX attribute values, TS enum members/module declarations/external
// module references, literal types, and import types) and whenever any
// other escape (`\n`, `\u`, `\x`, ...), a backtick, an interpolation
// delimiter, a trailing backslash, or a line break is involved — the
// cooked value would not survive the rewrite. The reverse
// "unnecessary String.raw" cleanup uses a different reference message and
// has no capture evidence, so it stays out of scope. The report anchors on
// the literal with the reference message "`String.raw` should be used to
// avoid escaping `\`." No auto-fix is offered.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope};
use hoonarqube_ir::Issue;

/// Entry point: `javascript:S7780` + `typescript:S7780`
/// prefer-string-raw check over the parsed program.
pub(crate) fn check(_ctx: &AnalysisContext) -> Vec<Issue> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    const MESSAGE: &str = "`String.raw` should be used to avoid escaping `\\`.";

    #[test]
    fn s7780_flags_pinned_axios_header_regex_anchors() {
        // Pinned anchor: axios/axios@18e7dfe
        // lib/helpers/sanitizeHeaderValue.js:34+36 — Sonar: `String.raw`
        // should be used to avoid escaping `\`.
        let source = "\
const INVALID_UNICODE_HEADER_VALUE_CHARS = new RegExp('[\\\\u0000-\\\\u0008\\\\u000a-\\\\u001f\\\\u007f]+', 'g');
const INVALID_BYTE_STRING_HEADER_VALUE_CHARS = new RegExp('[^\\\\u0009\\\\u0020-\\\\u007e\\\\u0080-\\\\u00ff]+', 'g');
";
        let report = js(source);
        let keys = report_keys(&report);
        assert_eq!(count_key(&keys, "javascript:S7780"), 2);
        for (line, name) in [(1u32, "INVALID_UNICODE_HEADER_VALUE_CHARS"), (2, "INVALID_BYTE_STRING_HEADER_VALUE_CHARS")] {
            let issue = report
                .issues
                .iter()
                .find(|issue| {
                    issue.rule_key == "javascript:S7780"
                        && issue.range.start.line == line
                })
                .expect("each pinned header regex literal must be reported");
            assert_eq!(issue.message, MESSAGE);
            let prefix = format!("const {name} = new RegExp(");
            assert_eq!(
                issue.range.start.column,
                u32::try_from(prefix.len()).unwrap()
            );
        }
    }

    #[test]
    fn s7780_flags_pinned_markdown_it_html_re_anchors() {
        // Pinned anchor: markdown-it/markdown-it@3c51991
        // src/common/html_re.ts:11/13/15 (+15/17 region) — templates and
        // string literals carrying only escaped backslashes; the backtick
        // literal on line 3 stays silent.
        let source = "\
const attr_name = '[a-zA-Z_:][a-zA-Z0-9:._-]*';

const unquoted = '[^\"\\'=<>`\\\\x00-\\\\x20]+';
const single_quoted = \"'[^']*'\";
const double_quoted = '\"[^\"]*\"';

const attr_value = `(?:${attr_name}|${single_quoted}|${double_quoted})`;

const attribute = `(?:\\\\s+${attr_name}(?:\\\\s*=\\\\s*${attr_value})?)`;

const open_tag = `<[A-Za-z][A-Za-z0-9\\\\-]*${attribute}*\\\\s*\\\\/?>`;

const close_tag = '<\\\\/[A-Za-z][A-Za-z0-9\\\\-]*\\\\s*>';
const comment = '<!---?>|<!--(?:[^-]|-[^-]|--[^>])*-->';
const processing = '<[?][\\\\s\\\\S]*?[?]>';
const declaration = '<![A-Za-z][^>]*>';
const cdata = '<!\\\\[CDATA\\\\[[\\\\s\\\\S]*?\\\\]\\\\]>';
";
        let keys = ts_keys(source);
        let flagged: Vec<u32> = keys
            .iter()
            .filter(|(key, _)| key == "typescript:S7780")
            .map(|(_, line)| *line)
            .collect();
        assert_eq!(flagged, vec![9, 11, 13, 15, 17]);
    }

    #[test]
    fn s7780_flags_pinned_zod_regex_source_templates() {
        // Pinned anchor: colinhacks/zod@46da957 packages/zod/src/v3/types.ts
        // 622/649/653.
        let source = "\
const _emojiRegex = `^[\\\\p{Extended_Pictographic}\\\\p{Emoji_Component}]+$`;
const dateRegexSource = `((\\\\d\\\\d[2468][048]|\\\\d\\\\d[13579][26]|\\\\d\\\\d0[48]|[02468][048]00|[13579][26]00)-02-29|\\\\d{4}-((0[13578]|1[02])-(0[1-9]|[12]\\\\d|3[01])|(0[469]|11)-(0[1-9]|[12]\\\\d|30)|(02)-(0[1-9]|1\\\\d|2[0-8])))`;
let secondsRegexSource = `[0-5]\\\\d`;
";
        let keys = ts_keys(source);
        let flagged: Vec<u32> = keys
            .iter()
            .filter(|(key, _)| key == "typescript:S7780")
            .map(|(_, line)| *line)
            .collect();
        assert_eq!(flagged, vec![1, 2, 3]);
    }

    #[test]
    fn s7780_controls_stay_silent() {
        let source = "\
const newline = 'a\\nb';
const unicode = '\\u0041';
const tagged = String.raw`a\\\\b`;
const preTagged = tag`\\\\d`;
const alreadyRaw = `plain ${'x'} text`;
const backtick = 'has ` backslash \\\\ here';
const key = { 'a\\\\b': 1 };
const trailing = 'ends \\\\';
const interpolated = `a\\\\${'b'}c`;
const mixed = `x\\\\y\\nz`;
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S7780"), 1);
        assert!(keys.contains(&("javascript:S7780".to_string(), 9)));
    }

    #[test]
    fn s7780_reports_in_both_languages() {
        let js_source = "const p = 'C:\\\\docs';\n";
        let ts_source = "const p = 'C:\\\\docs';\n";
        assert_eq!(count_key(&js_keys(js_source), "javascript:S7780"), 1);
        assert_eq!(count_key(&ts_keys(ts_source), "typescript:S7780"), 1);
    }
}
