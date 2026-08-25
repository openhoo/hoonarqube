use crate::engine::file_context::FileContext;
use crate::support::has_boto3_binding;
use crate::support::issue_at;
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
    // CE only evaluates boto3 client calls it can resolve to a real binding;
    // stub objects stay silent.
    if !has_boto3_binding(&file_ctx.calls) {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let open_auth = ["AuthorizationType", "authorizationType"]
            .iter()
            .find_map(|name| keyword_value(&call.arguments, name))
            .and_then(string_literal_text)
            .is_some_and(|value| value == "NONE");
        if open_auth {
            issues.push(issue_at(
                "python:S6333",
                "Require authentication for this API Gateway method.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}
