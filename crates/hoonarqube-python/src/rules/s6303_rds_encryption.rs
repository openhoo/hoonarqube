use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::has_keyword;
use crate::support::is_false_literal;
use crate::support::issue_at;
use crate::support::keyword_value;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6303 — RDS resources encrypted at rest ------------------------------

pub(crate) fn check_s6303_rds_encryption(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    const RDS_CREATORS: [&str; 4] = [
        "DatabaseCluster",
        "DatabaseInstance",
        "CfnDBCluster",
        "CfnDBInstance",
    ];
    if !file_ctx.has_aws_cdk_import {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let unencrypted = RDS_CREATORS.contains(&called_name(&call.func).unwrap_or_default())
            && (!has_keyword(&call.arguments, "storage_encrypted")
                || keyword_value(&call.arguments, "storage_encrypted")
                    .is_some_and(is_false_literal));
        if unencrypted {
            issues.push(issue_at(
                "python:S6303",
                "Omitting \"storage_encrypted\" and \"storage_encryption_key\" disables RDS encryption. Make sure it is safe here.",
                call.func.range(),
                index,
                source,
            ));
        }
    }
    issues
}
