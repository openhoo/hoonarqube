use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::dotted_name;
use crate::support::issue_at;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6883 — mismatched hour/AM-PM strftime specifiers ----------------------

pub(crate) fn check_strftime_hour_markers(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if called_name(&call.func) != Some("strftime")
            && dotted_name(&call.func).as_deref() != Some("strftime")
        {
            continue;
        }
        let Some(format_expr) = call.arguments.args.first() else {
            continue;
        };
        let Some(format) = string_literal_text(format_expr) else {
            continue;
        };
        let normalized = format.replace("%%", "");
        let twelve_hour_without_marker = normalized.contains("%I") && !normalized.contains("%p");
        let twentyfour_with_marker = normalized.contains("%H") && normalized.contains("%p");
        if twelve_hour_without_marker || twentyfour_with_marker {
            issues.push(issue_at(
                "python:S6883",
                "Match the hour specifier with an AM/PM marker in this format.",
                format_expr.range(),
                index,
                source,
            ));
        }
    }
    issues
}
