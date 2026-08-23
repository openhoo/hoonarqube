use crate::support::dotted_name;
use crate::support::for_each_call;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6887 / python:S6890 — pytz misuse --------------------------------------

pub(crate) fn check_pytz_timezone_usage(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if dotted_name(&call.func).as_deref() == Some("pytz.timezone") {
            issues.push(issue_at(
                "python:S6890",
                "Prefer zoneinfo.ZoneInfo over pytz.timezone.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
