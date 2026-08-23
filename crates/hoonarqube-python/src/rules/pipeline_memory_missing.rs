use crate::support::called_name;
use crate::support::for_each_call;
use crate::support::has_keyword;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_pipeline_memory_missing(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if called_name(&call.func) == Some("Pipeline") && !has_keyword(&call.arguments, "memory") {
            issues.push(issue_at(
                "python:S6969",
                "Pass a memory directory to enable Pipeline caching.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
