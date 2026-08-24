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

// --- python:S6319 — SageMaker notebook instances encrypted at rest ----------------

pub(crate) fn check_s6319_sagemaker_encryption(
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
    });
    issues
}
