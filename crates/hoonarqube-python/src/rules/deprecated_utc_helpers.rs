use crate::support::dotted_name;
use crate::support::for_each_call;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6903 — deprecated naive-UTC datetime helpers -----------------------

pub(crate) fn check_deprecated_utc_helpers(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    const DEPRECATED_UTC: [&str; 4] = [
        "datetime.datetime.utcnow",
        "datetime.datetime.utcfromtimestamp",
        "datetime.utcnow",
        "datetime.utcfromtimestamp",
    ];
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if dotted_name(&call.func).is_some_and(|p| DEPRECATED_UTC.contains(&p.as_str())) {
            issues.push(issue_at(
                "python:S6903",
                "Use timezone-aware datetime APIs instead of this deprecated helper.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
