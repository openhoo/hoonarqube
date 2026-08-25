use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::has_keyword;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_read_without_dtype(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if matches!(called_name(&call.func), Some("read_csv" | "read_table"))
            && !has_keyword(&call.arguments, "dtype")
        {
            issues.push(issue_at(
                "python:S6740",
                "Pass an explicit dtype when reading tabular data.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}
