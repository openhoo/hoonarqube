use crate::support::call_parts;
use crate::support::dotted_name;
use crate::support::for_each_call;
use crate::support::issue_at;
use crate::support::keyword_value;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_pytz_tzinfo_kwarg(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        let is_datetime_ctor = matches!(
            dotted_name(&call.func).as_deref(),
            Some("datetime.datetime" | "datetime")
        );
        if !is_datetime_ctor {
            return;
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
    });
    issues
}
