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
    // CE only evaluates boto3 client calls it can resolve to a real binding;
    // stub objects stay silent.
    if !file_ctx.has_boto3_binding {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if called_name(&call.func) == Some("create_queue")
            && !has_keyword(&call.arguments, "KmsMasterQueueId")
        {
            issues.push(issue_at(
                "python:S6330",
                "Encrypt this SQS queue with a KMS key.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}
