use crate::engine::file_context::FileContext;
use crate::support::call_subtree_open_world;
use crate::support::called_name;
use crate::support::has_boto3_binding;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6463 — security groups unrestricted egress ----------------------------

pub(crate) fn check_s6463_unrestricted_egress(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    // CE only evaluates boto3 client calls it can resolve to a real binding;
    // stub objects stay silent.
    if !has_boto3_binding(&file_ctx.calls) {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if called_name(&call.func) == Some("authorize_security_group_egress")
            && call_subtree_open_world(call)
        {
            issues.push(issue_at(
                "python:S6463",
                "Restrict this security group's egress traffic.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}
