use crate::AnalyzerOptions;
use crate::support::for_each_function_def;
use crate::support::issue_at;
use crate::support::to_u32;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

/// python:S107 — parameter count against `maximumFunctionParameters`;
/// `*args` and `**kwargs` each count as one parameter.
pub(crate) fn check_function_parameter_counts(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_function_def(
        parsed.syntax().body.as_slice(),
        false,
        &mut |function, _| {
            let parameters = &function.parameters;
            let count = parameters.posonlyargs.len()
                + parameters.args.len()
                + parameters.kwonlyargs.len()
                + usize::from(parameters.vararg.is_some())
                + usize::from(parameters.kwarg.is_some());
            let maximum = options.maximum_function_parameters;
            if to_u32(count) > maximum {
                issues.push(issue_at(
                    "python:S107",
                    &format!(
                        "Function \"{}\" has {count} parameters, which is greater than the \
                         {maximum} authorized.",
                        function.name
                    ),
                    ruff_text_size::TextRange::new(
                        function.parameters.start() + ruff_text_size::TextSize::new(1),
                        function.parameters.end() - ruff_text_size::TextSize::new(1),
                    ),
                    index,
                    source,
                ));
            }
        },
    );
    issues
}
