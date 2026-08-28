use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::has_keyword;
use crate::support::is_true_literal;
use crate::support::issue_at;
use crate::support::keyword_value;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6463 — security groups unrestricted egress ----------------------------

pub(crate) fn check_s6463_unrestricted_egress(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    if !file_ctx.has_aws_cdk_import {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if called_name(&call.func) == Some("SecurityGroup")
            && (!has_keyword(&call.arguments, "allow_all_outbound")
                || keyword_value(&call.arguments, "allow_all_outbound")
                    .is_some_and(is_true_literal))
        {
            issues.push(issue_at(
                "python:S6463",
                "Omitting \"allow_all_outbound\" enables unrestricted outbound communications. Make sure it is safe here.",
                call.func.range(),
                index,
                source,
            ));
        }
    }
    issues
}
