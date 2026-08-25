use crate::engine::file_context::FileContext;
use crate::support::dotted_name;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6903 — deprecated naive-UTC datetime helpers -----------------------

pub(crate) fn check_deprecated_utc_helpers(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    const DEPRECATED_UTC: [&str; 4] = [
        "datetime.datetime.utcnow",
        "datetime.datetime.utcfromtimestamp",
        "datetime.utcnow",
        "datetime.utcfromtimestamp",
    ];
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if dotted_name(&call.func).is_some_and(|p| DEPRECATED_UTC.contains(&p.as_str())) {
            issues.push(issue_at(
                "python:S6903",
                "Use timezone-aware datetime APIs instead of this deprecated helper.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}
