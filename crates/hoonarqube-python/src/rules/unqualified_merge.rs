use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::has_keyword;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_unqualified_merge(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if !matches!(called_name(&call.func), Some("merge" | "join")) {
            continue;
        }
        let qualified = ["on", "left_on", "right_on", "how", "validate"]
            .iter()
            .any(|name| has_keyword(&call.arguments, name));
        if !qualified {
            issues.push(issue_at(
                "python:S6735",
                "Make this join explicit with on/how or validate arguments.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}
