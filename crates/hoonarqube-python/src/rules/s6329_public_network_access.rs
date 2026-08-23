use crate::support::PUBLIC_NETWORK_FLAGS;
use crate::support::for_each_call;
use crate::support::issue_at;
use crate::support::sets_true_flag;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s6329_public_network_access(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if PUBLIC_NETWORK_FLAGS
            .iter()
            .any(|flag| sets_true_flag(call, flag))
        {
            issues.push(issue_at(
                "python:S6329",
                "Disable public network access for this resource.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
