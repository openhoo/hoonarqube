use crate::engine::file_context::FileContext;
use crate::support::call_subtree_has_port;
use crate::support::call_subtree_open_world;
use crate::support::called_name;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s6321_admin_ports_open_world(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    // CE only evaluates boto3 client calls it can resolve to a real binding;
    // stub objects stay silent.
    if !file_ctx.has_boto3_binding {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if called_name(&call.func) == Some("authorize_security_group_ingress")
            && call_subtree_open_world(call)
            && call_subtree_has_port(call, &ADMIN_PORTS)
        {
            issues.push(issue_at(
                "python:S6321",
                "Restrict this administrative port instead of opening it to the whole internet.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}

// --- python:S6321 — administration services restricted by IP ----------------------

const ADMIN_PORTS: [i64; 2] = [22, 3389];
