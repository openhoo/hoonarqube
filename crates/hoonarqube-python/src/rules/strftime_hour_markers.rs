use crate::support::called_name;
use crate::support::dotted_name;
use crate::support::for_each_call;
use crate::support::issue_at;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6883 — mismatched hour/AM-PM strftime specifiers ----------------------

pub(crate) fn check_strftime_hour_markers(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if called_name(&call.func) != Some("strftime")
            && dotted_name(&call.func).as_deref() != Some("strftime")
        {
            return;
        }
        let Some(format_expr) = call.arguments.args.first() else {
            return;
        };
        let Some(format) = string_literal_text(format_expr) else {
            return;
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
    });
    issues
}
