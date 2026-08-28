use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::issue_at;
use crate::support::keyword_range;
use crate::support::keyword_value;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6333 — API Gateway requests authenticated ----------------------------

pub(crate) fn check_s6333_api_gateway_authorization(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    if !file_ctx.has_aws_cdk_import {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let open_auth = matches!(called_name(&call.func), Some("add_method" | "CfnRoute"))
            && keyword_value(&call.arguments, "authorization_type").is_some_and(|value| {
                string_literal_text(value).as_deref() == Some("NONE")
                    || source[value.range()].split('.').next_back() == Some("NONE")
            });
        if open_auth {
            issues.push(issue_at(
                "python:S6333",
                "Make sure that creating public APIs is safe here.",
                keyword_range(&call.arguments, "authorization_type")
                    .unwrap_or_else(|| call.range()),
                index,
                source,
            ));
        }
    }
    issues
}
