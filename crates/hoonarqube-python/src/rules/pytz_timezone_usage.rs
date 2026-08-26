use crate::engine::file_context::FileContext;
use crate::support::dotted_name_is;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6887 / python:S6890 — pytz misuse --------------------------------------

pub(crate) fn check_pytz_timezone_usage(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if dotted_name_is(&call.func, "pytz.timezone") {
            issues.push(issue_at(
                "python:S6890",
                "Prefer zoneinfo.ZoneInfo over pytz.timezone.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}
