use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::has_keyword;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6319 — SageMaker notebook instances encrypted at rest ----------------

pub(crate) fn check_s6319_sagemaker_encryption(
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
        if called_name(&call.func) == Some("create_notebook_instance")
            && !has_keyword(&call.arguments, "VolumeKmsKeyId")
        {
            issues.push(issue_at(
                "python:S6319",
                "Encrypt this SageMaker notebook instance at rest.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}
