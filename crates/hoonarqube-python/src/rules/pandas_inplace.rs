use crate::engine::file_context::FileContext;
use crate::support::PANDAS_INPLACE_METHODS;
use crate::support::called_name;
use crate::support::is_true_literal;
use crate::support::issue_at;
use crate::support::keyword_value;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_pandas_inplace(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if called_name(&call.func).is_some_and(|name| PANDAS_INPLACE_METHODS.contains(&name))
            && keyword_value(&call.arguments, "inplace").is_some_and(is_true_literal)
        {
            issues.push(issue_at(
                "python:S6734",
                "Avoid inplace=True; assign the result explicitly instead.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}
