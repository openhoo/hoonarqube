use crate::support::dict_string_entry;
use crate::support::for_each_dict_literal;
use crate::support::has_boto3_binding;
use crate::support::includes_wildcard;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6304 — IAM policies scoped away from all resources -----------------

pub(crate) fn check_s6304_all_resources_policy(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    // CE only evaluates policies in files with a resolvable boto3 binding;
    // stub-only files stay silent.
    if !has_boto3_binding(parsed.syntax().body.as_slice()) {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for_each_dict_literal(parsed.syntax().body.as_slice(), &mut |dict| {
        if dict_string_entry(dict, "Resource").is_some_and(includes_wildcard) {
            issues.push(issue_at(
                "python:S6304",
                "Scope this policy to specific resources instead of all resources.",
                dict.range(),
                index,
                source,
            ));
        }
    });
    issues
}
