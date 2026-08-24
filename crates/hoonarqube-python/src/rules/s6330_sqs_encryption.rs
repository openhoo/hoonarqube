use crate::support::called_name;
use crate::support::for_each_call;
use crate::support::has_boto3_binding;
use crate::support::has_keyword;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6330 — SQS queues encrypted ----------------------------------------

pub(crate) fn check_s6330_sqs_encryption(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    // CE only evaluates boto3 client calls it can resolve to a real binding;
    // stub objects stay silent.
    if !has_boto3_binding(parsed.syntax().body.as_slice()) {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
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
    });
    issues
}
