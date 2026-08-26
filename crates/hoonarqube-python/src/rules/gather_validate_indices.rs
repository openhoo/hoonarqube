use crate::engine::file_context::FileContext;
use crate::support::dotted_name_is;
use crate::support::has_keyword;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_gather_validate_indices(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if dotted_name_is(&call.func, "tf.gather")
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
    }
    issues
}
