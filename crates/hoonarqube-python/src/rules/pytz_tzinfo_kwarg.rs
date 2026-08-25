use crate::engine::file_context::FileContext;
use crate::support::call_parts;
use crate::support::dotted_name;
use crate::support::issue_at;
use crate::support::keyword_value;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_pytz_tzinfo_kwarg(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let is_datetime_ctor = matches!(
            dotted_name(&call.func).as_deref(),
            Some("datetime.datetime" | "datetime")
        );
        if !is_datetime_ctor {
            continue;
        }
        if let Some(tzinfo) = keyword_value(&call.arguments, "tzinfo")
            && call_parts(tzinfo).is_some_and(|(path, _)| path == "pytz.timezone")
        {
            issues.push(issue_at(
                "python:S6887",
                "Constructing datetimes with pytz.timezone through tzinfo mislocalizes them.",
                tzinfo.range(),
                index,
                source,
            ));
        }
    }
    issues
}
