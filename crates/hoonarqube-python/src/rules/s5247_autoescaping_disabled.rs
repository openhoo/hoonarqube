use crate::support::autoescape_off;
use crate::support::for_each_call;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s5247_autoescaping_disabled(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if autoescape_off(call) {
            issues.push(issue_at(
                "python:S5247",
                "Do not disable HTML auto-escaping in this template engine configuration.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
