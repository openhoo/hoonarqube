use crate::support::PUBLIC_ACCESS_BLOCK_KEYS;
use crate::support::call_source_text;
use crate::support::called_name;
use crate::support::for_each_call;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s6281_s3_public_access_block(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if called_name(&call.func) != Some("put_public_access_block") {
            return;
        }
        let call_text = call_source_text(call, source);
        let fully_blocked = PUBLIC_ACCESS_BLOCK_KEYS
            .iter()
            .all(|key| call_text.contains(key));
        if !fully_blocked {
            issues.push(issue_at(
                "python:S6281",
                "Block all four public access settings for this S3 bucket.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
