use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::has_keyword;
use crate::support::is_true_literal;
use crate::support::issue_at;
use crate::support::keyword_value;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_to_datetime_ambiguity(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if called_name(&call.func) != Some("to_datetime") || has_keyword(&call.arguments, "format")
        {
            continue;
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
    }
    issues
}
