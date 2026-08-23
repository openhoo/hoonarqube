use crate::support::for_each_method;
use crate::support::has_decorator;
use crate::support::issue_at;
use crate::support::positional_parameters;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_methods_missing_parameters(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_method(parsed.syntax().body.as_slice(), &mut |_class, function| {
        if !has_decorator(function, "staticmethod")
            && positional_parameters(&function.parameters).is_empty()
        {
            issues.push(issue_at(
                "python:S5719",
                "Add the missing instance or class method parameter ('self' or 'cls').",
                function.name.range(),
                index,
                source,
            ));
        }
    });
    issues
}
