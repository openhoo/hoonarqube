use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::issue_at;
use crate::support::keyword_value;
use crate::support::wildcard_literal;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6304 — IAM policies scoped away from all resources -----------------

pub(crate) fn check_s6304_all_resources_policy(
    _parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    // SonarPython scopes this rule to AWS CDK PolicyStatement calls.
    if !file_ctx.has_aws_cdk_import {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if called_name(&call.func) == Some("PolicyStatement")
            && let Some(wildcard) =
                keyword_value(&call.arguments, "resources").and_then(wildcard_literal)
        {
            issues.push(issue_at(
                "python:S6304",
                "Make sure granting access to all resources is safe here.",
                wildcard.range(),
                index,
                source,
            ));
        }
    }
    issues
}
