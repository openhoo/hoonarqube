use crate::support::called_name;
use crate::support::for_each_call;
use crate::support::has_keyword;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5042 — archive extraction without resource control ---------------

pub(crate) fn check_unbounded_archive_extraction(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if called_name(&call.func) == Some("extractall") && !has_keyword(&call.arguments, "members")
        {
            issues.push(issue_at(
                "python:S5042",
                "Limit this archive extraction with a members filter.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
