use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::is_true_literal;
use crate::support::issue_at;
use crate::support::keyword_range;
use crate::support::keyword_value;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s6329_public_network_access(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    if !file_ctx.has_aws_cdk_import {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if PUBLIC_RESOURCE_CREATORS.contains(&called_name(&call.func).unwrap_or_default())
            && keyword_value(&call.arguments, "publicly_accessible").is_some_and(is_true_literal)
        {
            issues.push(issue_at(
                "python:S6329",
                "Make sure allowing public network access is safe here.",
                keyword_range(&call.arguments, "publicly_accessible")
                    .unwrap_or_else(|| call.range()),
                index,
                source,
            ));
        }
    }
    issues
}

// --- python:S6329 — public network access disabled ----------------------------------

const PUBLIC_RESOURCE_CREATORS: [&str; 2] = ["CfnReplicationInstance", "CfnDBInstance"];
