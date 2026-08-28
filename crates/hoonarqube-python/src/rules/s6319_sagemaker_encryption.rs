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
    if !file_ctx.has_aws_cdk_import {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if called_name(&call.func) == Some("CfnNotebookInstance")
            && !has_keyword(&call.arguments, "kms_key_id")
        {
            issues.push(issue_at(
                "python:S6319",
                "Omitting kms_key_id disables encryption of SageMaker notebook instances. Make sure it is safe here.",
                call.func.range(),
                index,
                source,
            ));
        }
    }
    issues
}
