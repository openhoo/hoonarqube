use crate::support::WEAK_PROTOCOL_CONSTANTS;
use crate::support::for_each_attr_load;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s4423_weak_ssl_protocols(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for protocol in WEAK_PROTOCOL_CONSTANTS {
        for_each_attr_load(parsed.syntax().body.as_slice(), protocol, |attr| {
            issues.push(issue_at(
                "python:S4423",
                "Replace this weak SSL/TLS protocol with a modern alternative.",
                attr.range(),
                index,
                source,
            ));
        });
    }
    issues
}
