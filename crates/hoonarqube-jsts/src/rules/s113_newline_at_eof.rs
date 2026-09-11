// Rule module s113_newline_at_eof (generated).

use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::support::{LineIndex, to_u32};
use hoonarqube_ir::Issue;

fn ends_with_ecmascript_line_terminator(source: &str) -> bool {
    matches!(
        source.chars().next_back(),
        Some('\r' | '\n' | '\u{2028}' | '\u{2029}')
    )
}

fn check_missing_newline_at_eof(
    source: &str,
    language: JstsLanguage,
    index: &LineIndex,
) -> Vec<Issue> {
    // Empty files have no last byte to violate the rule.
    if source.is_empty() || ends_with_ecmascript_line_terminator(source) {
        return Vec::new();
    }
    let end = index.pos(to_u32(source.len()));
    vec![Issue {
        rule_key: format!("{}:S113", language.prefix()),
        message: "Newline required at end of file but not found.".to_string(),
        range: hoonarqube_ir::Range {
            start: hoonarqube_ir::Pos {
                line: end.line,
                column: 0,
            },
            end,
        },
        fix: None,
        flows: Vec::new(),
        alternatives: Vec::new(),
    }]
}

pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    check_missing_newline_at_eof(ctx.source, ctx.language, ctx.index)
}
#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn missing_final_newline_is_flagged_once_per_file() {
        let missing = js_keys("let a = 1;");
        assert_eq!(count_key(&missing, "javascript:S113"), 1);

        let missing_ts = ts_keys("let a = 1;");
        assert_eq!(count_key(&missing_ts, "typescript:S113"), 1);

        let terminated = js_keys("let a = 1;\n");
        assert_eq!(count_key(&terminated, "javascript:S113"), 0);
        let terminated_cr = js_keys("let a = 1;\r");
        assert_eq!(count_key(&terminated_cr, "javascript:S113"), 0);

        let terminated_crlf = js_keys("let a = 1;\r\n");
        assert_eq!(count_key(&terminated_crlf, "javascript:S113"), 0);

        let terminated_line_separator = js_keys("let a = 1;\u{2028}");
        assert_eq!(count_key(&terminated_line_separator, "javascript:S113"), 0);

        let terminated_paragraph_separator = js_keys("let a = 1;\u{2029}");
        assert_eq!(
            count_key(&terminated_paragraph_separator, "javascript:S113"),
            0
        );

        let no_final_terminator = js_keys("let a = 1;\rlet b = 2;");
        assert_eq!(count_key(&no_final_terminator, "javascript:S113"), 1);
    }

    #[test]
    fn empty_source_never_violates_newline_at_eof() {
        let empty = js("");
        assert_eq!(count_key(&report_keys(&empty), "javascript:S113"), 0);
    }
}
