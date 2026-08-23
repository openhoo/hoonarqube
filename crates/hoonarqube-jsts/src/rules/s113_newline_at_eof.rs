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
