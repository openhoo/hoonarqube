use crate::support::for_each_call;
use crate::support::has_boto3_binding;
use crate::support::issue_at;
use crate::support::sets_true_flag;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s6329_public_network_access(
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
    });
    issues
}

// --- migrated from support/mod.rs (S6329) ---
// --- python:S6329 — public network access disabled ----------------------------------

pub(crate) const PUBLIC_NETWORK_FLAGS: [&str; 3] = [
    "PubliclyAccessible",
    "MapPublicIpOnLaunch",
    "AssociatePublicIpAddress",
];
