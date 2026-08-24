use crate::support::for_each_call;
use crate::support::has_boto3_binding;
use crate::support::issue_at;
use crate::support::keyword_value;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6333 — API Gateway requests authenticated ----------------------------

pub(crate) fn check_s6333_api_gateway_authorization(
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
    });
    issues
}
