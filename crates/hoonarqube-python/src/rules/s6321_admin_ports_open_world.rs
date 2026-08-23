use crate::support::ADMIN_PORTS;
use crate::support::call_subtree_has_port;
use crate::support::call_subtree_open_world;
use crate::support::called_name;
use crate::support::for_each_call;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s6321_admin_ports_open_world(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
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
    });
    issues
}
