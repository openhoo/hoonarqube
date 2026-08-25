use crate::engine::file_context::FileContext;
use crate::support::dotted_name;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5445 — insecure temporary files ----------------------------------

pub(crate) fn check_insecure_temp_files(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let insecure = ["tempfile.mktemp", "os.tempnam", "os.tmpnam"];
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if dotted_name(&call.func).is_some_and(|path| insecure.contains(&path.as_str())) {
            issues.push(issue_at(
                "python:S5445",
                "Remove this usage of the deprecated insecure temporary file API.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}
