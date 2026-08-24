use crate::support::call_subtree_open_world;
use crate::support::called_name;
use crate::support::for_each_call;
use crate::support::has_boto3_binding;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6463 — security groups unrestricted egress ----------------------------

pub(crate) fn check_s6463_unrestricted_egress(
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
        if called_name(&call.func) == Some("authorize_security_group_egress")
            && call_subtree_open_world(call)
        {
            issues.push(issue_at(
                "python:S6463",
                "Restrict this security group's egress traffic.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
