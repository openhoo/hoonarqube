use crate::engine::file_context::FileContext;
use crate::support::dotted_name_in;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6729 — single-argument np.where ------------------------------------

pub(crate) fn check_single_arg_np_where(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if dotted_name_in(&call.func, &["np.where", "numpy.where"])
            && call.arguments.args.len() == 1
            && call.arguments.keywords.is_empty()
        {
            issues.push(issue_at(
                "python:S6729",
                "Prefer np.nonzero over a single-argument np.where.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}
