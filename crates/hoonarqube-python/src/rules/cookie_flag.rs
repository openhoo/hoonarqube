use crate::engine::file_context::FileContext;
use crate::support::cookie_flag_missing;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_cookie_flag(
    index: &LineIndex,
    source: &str,
    rule_key: &str,
    message: &str,
    flag: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if cookie_flag_missing(call, flag) {
            issues.push(issue_at(rule_key, message, call.range(), index, source));
        }
    }
    issues
}
