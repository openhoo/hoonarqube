use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::has_keyword;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5042 — archive extraction without resource control ---------------

pub(crate) fn check_unbounded_archive_extraction(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
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
    }
    issues
}
