use crate::support::dict_string_entry;
use crate::support::for_each_dict_literal;
use crate::support::includes_wildcard;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6302 — policies granting all privileges -----------------------------

pub(crate) fn check_s6302_all_privileges_policy(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_dict_literal(parsed.syntax().body.as_slice(), &mut |dict| {
        if dict_string_entry(dict, "Action").is_some_and(includes_wildcard) {
            issues.push(issue_at(
                "python:S6302",
                "Scope this policy's actions instead of granting all privileges.",
                dict.range(),
                index,
                source,
            ));
        }
    });
    issues
}
