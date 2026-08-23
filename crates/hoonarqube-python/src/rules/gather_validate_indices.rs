use crate::support::dotted_name;
use crate::support::for_each_call;
use crate::support::has_keyword;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_gather_validate_indices(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if dotted_name(&call.func).as_deref() == Some("tf.gather")
            && has_keyword(&call.arguments, "validate_indices")
        {
            issues.push(issue_at(
                "python:S6925",
                "Remove the deprecated validate_indices argument.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
