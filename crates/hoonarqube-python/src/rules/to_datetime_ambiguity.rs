use crate::support::called_name;
use crate::support::for_each_call;
use crate::support::has_keyword;
use crate::support::is_true_literal;
use crate::support::issue_at;
use crate::support::keyword_value;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_to_datetime_ambiguity(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if called_name(&call.func) != Some("to_datetime") || has_keyword(&call.arguments, "format")
        {
            return;
        }
        let ambiguous = ["dayfirst", "yearfirst"]
            .iter()
            .any(|name| keyword_value(&call.arguments, name).is_some_and(is_true_literal));
        if ambiguous {
            issues.push(issue_at(
                "python:S6894",
                "Resolve dayfirst/yearfirst ambiguity with an explicit format.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
