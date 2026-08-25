use crate::engine::file_context::FileContext;
use crate::support::call_source_text;
use crate::support::called_name;
use crate::support::has_boto3_binding;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s6281_s3_public_access_block(
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
        if called_name(&call.func) != Some("put_public_access_block") {
            continue;
        }
        let call_text = call_source_text(call, source);
        let fully_blocked = PUBLIC_ACCESS_BLOCK_KEYS
            .iter()
            .all(|key| call_text.contains(key));
        if !fully_blocked {
            issues.push(issue_at(
                "python:S6281",
                "Block all four public access settings for this S3 bucket.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}

// --- migrated from support/mod.rs (S6281) ---
// --- python:S6281 — S3 public access fully blocked --------------------------------

const PUBLIC_ACCESS_BLOCK_KEYS: [&str; 4] = [
    "BlockPublicAcls",
    "BlockPublicPolicy",
    "IgnorePublicAcls",
    "RestrictPublicBuckets",
];
