// Rule module s113_newline_at_eof (generated).

use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::support::{LineIndex, to_u32};
use hoonarqube_ir::Issue;

pub(crate) fn check_missing_newline_at_eof(
    source: &str,
    language: JstsLanguage,
    index: &LineIndex,
) -> Vec<Issue> {
    // Empty files have no last byte to violate the rule.
    if source.is_empty() || source.ends_with('\n') {
        return Vec::new();
    }
    let end = index.pos(to_u32(source.len()));
    vec![Issue {
        rule_key: format!("{}:S113", language.prefix()),
        message: "Add a new line at the end of this file.".to_string(),
        range: hoonarqube_ir::Range {
            start: end.clone(),
            end,
        },
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
    }

    #[test]
    fn empty_source_never_violates_newline_at_eof() {
        let empty = js("");
        assert_eq!(count_key(&report_keys(&empty), "javascript:S113"), 0);
    }
}
