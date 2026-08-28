use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::has_keyword;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6308 — OpenSearch domains encrypted at rest --------------------------

pub(crate) fn check_s6308_opensearch_encryption(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    const DOMAIN_CREATORS: [&str; 2] = ["Domain", "CfnDomain"];
    if !file_ctx.has_aws_cdk_import {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if DOMAIN_CREATORS.contains(&called_name(&call.func).unwrap_or_default())
            && !has_keyword(&call.arguments, "encryption_at_rest")
            && !has_keyword(&call.arguments, "encryption_at_rest_options")
        {
            issues.push(issue_at(
                "python:S6308",
                "Omitting encryption_at_rest causes encryption of data at rest to be disabled for this OpenSearch domain. Make sure it is safe here.",
                call.func.range(),
                index,
                source,
            ));
        }
    }
    issues
}
