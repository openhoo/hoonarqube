use crate::support::for_each_call;
use crate::support::issue_at;
use crate::support::unconditional_assert_verdict;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_unconditional_assertions(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if let Some(verdict) = unconditional_assert_verdict(call, source) {
            issues.push(issue_at(
                "python:S5914",
                &format!("This assertion always {verdict}."),
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
