use crate::engine::file_context::FileContext;
use crate::support::call_source_text;
use crate::support::called_name;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s6281_s3_public_access_block(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    // SonarPython scopes this rule to AWS CDK constructs.
    if !file_ctx.has_aws_cdk_import {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if called_name(&call.func) != Some("Bucket") {
            continue;
        }
        let call_text = call_source_text(call, source);
        let fully_blocked = call_text.contains("BlockPublicAccess.BLOCK_ALL")
            || PUBLIC_ACCESS_BLOCK_KEYS
                .iter()
                .all(|key| call_text.contains(key));
        if !fully_blocked {
            issues.push(issue_at(
                "python:S6281",
                "No Public Access Block configuration prevents public ACL/policies to be set on this S3 bucket. Make sure it is safe here.",
                call.func.range(),
                index,
                source,
            ));
        }
    }
    issues
}

// --- python:S6281 — S3 public access fully blocked --------------------------------

const PUBLIC_ACCESS_BLOCK_KEYS: [&str; 4] = [
    "block_public_acls=True",
    "block_public_policy=True",
    "ignore_public_acls=True",
    "restrict_public_buckets=True",
];
