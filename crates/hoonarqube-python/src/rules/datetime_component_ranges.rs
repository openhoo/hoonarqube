use crate::support::datetime_component_limit;
use crate::support::dotted_name;
use crate::support::for_each_call;
use crate::support::int_literal_value;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_datetime_component_ranges(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        let Some(path) = dotted_name(&call.func) else {
            return;
        };
        for (position, argument) in call.arguments.args.iter().enumerate() {
            let Some((low, high)) = datetime_component_limit(&path, position) else {
                break;
            };
            if let Some(value) = int_literal_value(argument)
                && !(low..=high).contains(&value)
            {
                issues.push(issue_at(
                    "python:S6882",
                    &format!("This datetime component must be between {low} and {high}."),
                    argument.range(),
                    index,
                    source,
                ));
            }
        }
    });
    issues
}
