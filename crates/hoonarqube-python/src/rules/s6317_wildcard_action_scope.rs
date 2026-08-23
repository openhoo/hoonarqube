use crate::support::action_scope_wildcards;
use crate::support::dict_string_entry;
use crate::support::for_each_dict_literal;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s6317_wildcard_action_scope(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_dict_literal(parsed.syntax().body.as_slice(), &mut |dict| {
        if dict_string_entry(dict, "Action").is_some_and(action_scope_wildcards) {
            issues.push(issue_at(
                "python:S6317",
                "Limit the scope of these IAM permissions.",
                dict.range(),
                index,
                source,
            ));
        }
    });
    issues
}
