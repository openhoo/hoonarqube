use crate::AnalyzerOptions;
use crate::support::for_each_function_def;
use crate::support::issue_at;
use crate::support::to_u32;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

/// python:S138 — function line span against `maximumFunctionLength`.
pub(crate) fn check_function_lengths(
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
            let start_line = index
                .line_column(function.range().start(), source)
                .line
                .get();
            let end_line = index.line_column(function.range().end(), source).line.get();
            let lines = end_line - start_line + 1;
            let maximum = options.maximum_function_length;
            if to_u32(lines) > maximum {
                issues.push(issue_at(
                    "python:S138",
                    &format!(
                        "This function has {lines} lines, which is greater than the \
                     {maximum} authorized."
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
