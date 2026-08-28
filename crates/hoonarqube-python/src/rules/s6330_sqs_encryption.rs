use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::has_keyword;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6330 — SQS queues encrypted ----------------------------------------

pub(crate) fn check_s6330_sqs_encryption(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    if !file_ctx.has_aws_cdk_import {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if matches!(called_name(&call.func), Some("Queue" | "CfnQueue"))
            && !has_keyword(&call.arguments, "encryption")
            && !has_keyword(&call.arguments, "kms_master_key_id")
        {
            issues.push(issue_at(
                "python:S6330",
                "Omitting \"kms_master_key_id\" disables SQS queues encryption. Make sure it is safe here.",
                call.func.range(),
                index,
                source,
            ));
        }
    }
    issues
}
