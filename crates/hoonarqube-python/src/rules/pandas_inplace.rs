use crate::support::PANDAS_INPLACE_METHODS;
use crate::support::called_name;
use crate::support::for_each_call;
use crate::support::is_true_literal;
use crate::support::issue_at;
use crate::support::keyword_value;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_pandas_inplace(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
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
    });
    issues
}
