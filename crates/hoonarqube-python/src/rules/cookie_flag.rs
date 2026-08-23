use crate::support::cookie_flag_missing;
use crate::support::for_each_call;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_cookie_flag(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    rule_key: &str,
    message: &str,
    flag: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if cookie_flag_missing(call, flag) {
            issues.push(issue_at(rule_key, message, call.range(), index, source));
        }
    });
    issues
}
