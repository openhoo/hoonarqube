use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::has_keyword;
use crate::support::is_false_literal;
use crate::support::issue_at;
use crate::support::keyword_range;
use crate::support::keyword_value;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6332 — EFS file systems encrypted -----------------------------------

pub(crate) fn check_s6332_efs_encryption(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    if !file_ctx.has_aws_cdk_import {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if matches!(
            called_name(&call.func),
            Some("FileSystem" | "CfnFileSystem")
        ) && (!has_keyword(&call.arguments, "encrypted")
            || keyword_value(&call.arguments, "encrypted").is_some_and(is_false_literal))
        {
            issues.push(issue_at(
                "python:S6332",
                "Make sure that using unencrypted file systems is safe here.",
                keyword_range(&call.arguments, "encrypted").unwrap_or_else(|| call.func.range()),
                index,
                source,
            ));
        }
    }
    issues
}
