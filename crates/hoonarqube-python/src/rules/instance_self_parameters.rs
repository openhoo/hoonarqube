use crate::support::for_each_method;
use crate::support::has_decorator;
use crate::support::issue_at;
use crate::support::positional_parameters;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5720 — `self` must be the first instance-method parameter --------

pub(crate) fn check_instance_self_parameters(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_method(parsed.syntax().body.as_slice(), &mut |_class, function| {
        if has_decorator(function, "staticmethod") || has_decorator(function, "classmethod") {
            return;
        }
        if let Some(first) = positional_parameters(&function.parameters).first()
            && first.name.as_str() != "self"
        {
            issues.push(issue_at(
                "python:S5720",
                "Rename this first parameter to 'self'.",
                first.name.range(),
                index,
                source,
            ));
        }
    });
    issues
}
