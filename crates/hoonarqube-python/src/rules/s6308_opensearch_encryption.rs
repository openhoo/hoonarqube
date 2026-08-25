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
    const DOMAIN_CREATORS: [&str; 2] = ["create_domain", "create_elasticsearch_domain"];
    // CE only evaluates boto3 client calls it can resolve to a real binding;
    // stub objects stay silent.
    if !file_ctx.has_boto3_binding {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if DOMAIN_CREATORS.contains(&called_name(&call.func).unwrap_or_default())
            && !has_keyword(&call.arguments, "EncryptionAtRestOptions")
        {
            issues.push(issue_at(
                "python:S6308",
                "Enable encryption at rest for this OpenSearch domain.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}
