use crate::support::collect_string_contents;
use crate::support::ip_addresses;
use crate::support::to_range;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

// ---------------------------------------------------------------------------
// python:S1313 — hardcoded IP addresses in string literals.
// ---------------------------------------------------------------------------

pub(crate) fn check_hardcoded_ips(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (text, range) in collect_string_contents(parsed.syntax().body.as_slice()) {
        if !ip_addresses(&text).is_empty() {
            issues.push(Issue {
                rule_key: "python:S1313".to_string(),
                message: "Make this IP address configurable.".to_string(),
                range: to_range(range, index, source),
            });
        }
    }
    issues
}
