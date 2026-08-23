use crate::support::dict_string_entry;
use crate::support::for_each_dict_literal;
use crate::support::grants_to_all_principals;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6270 — resource-based policies granting public access --------------

pub(crate) fn check_s6270_public_resource_policy(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_dict_literal(parsed.syntax().body.as_slice(), &mut |dict| {
        if dict_string_entry(dict, "Principal").is_some_and(grants_to_all_principals) {
            issues.push(issue_at(
                "python:S6270",
                "Restrict this resource policy instead of granting public access.",
                dict.range(),
                index,
                source,
            ));
        }
    });
    issues
}
