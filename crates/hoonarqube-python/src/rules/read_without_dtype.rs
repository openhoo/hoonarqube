use crate::support::called_name;
use crate::support::for_each_call;
use crate::support::has_keyword;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_read_without_dtype(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if matches!(called_name(&call.func), Some("read_csv" | "read_table"))
            && !has_keyword(&call.arguments, "dtype")
        {
            issues.push(issue_at(
                "python:S6740",
                "Pass an explicit dtype when reading tabular data.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
