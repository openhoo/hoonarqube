use crate::support::for_each_function_def;
use crate::support::issue_at;
use crate::support::matches_snake_case;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

/// Methods (functions declared directly in a class body) are python:S100;
/// module-level and nested functions are python:S1542.
pub(crate) fn check_method_and_function_names(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_function_def(
        parsed.syntax().body.as_slice(),
        false,
        &mut |function, in_class_body| {
            if !matches_snake_case(function.name.as_str()) {
                let (rule_key, kind) = if in_class_body {
                    ("python:S100", "method")
                } else {
                    ("python:S1542", "function")
                };
                issues.push(issue_at(
                    rule_key,
                    &format!(
                        "Rename this {kind} to match the regular expression '^[a-z_][a-z0-9_]*$'."
                    ),
                    function.name.range(),
                    index,
                    source,
                ));
            }
        },
    );
    issues
}
