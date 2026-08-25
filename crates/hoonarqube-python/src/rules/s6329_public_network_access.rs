use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use crate::support::sets_true_flag;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s6329_public_network_access(
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
        if PUBLIC_NETWORK_FLAGS
            .iter()
            .any(|flag| sets_true_flag(call, flag))
        {
            issues.push(issue_at(
                "python:S6329",
                "Disable public network access for this resource.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}

// --- python:S6329 — public network access disabled ----------------------------------

const PUBLIC_NETWORK_FLAGS: [&str; 3] = [
    "PubliclyAccessible",
    "MapPublicIpOnLaunch",
    "AssociatePublicIpAddress",
];
