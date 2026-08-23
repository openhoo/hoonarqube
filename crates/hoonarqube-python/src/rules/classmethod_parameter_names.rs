use crate::support::for_each_method;
use crate::support::has_decorator;
use crate::support::issue_at;
use crate::support::positional_parameters;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S2710 — classmethod first argument naming --------------------------

pub(crate) fn check_classmethod_parameter_names(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_method(parsed.syntax().body.as_slice(), &mut |_class, function| {
        if !has_decorator(function, "classmethod") {
            return;
        }
        if let Some(first) = positional_parameters(&function.parameters).first()
            && !matches!(first.name.as_str(), "cls" | "mcs" | "metacls")
        {
            issues.push(issue_at(
                "python:S2710",
                "Rename this first parameter to 'cls'.",
                first.name.range(),
                index,
                source,
            ));
        }
    });
    issues
}
