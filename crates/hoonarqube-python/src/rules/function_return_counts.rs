use crate::AnalyzerOptions;
use crate::support::count_own_returns;
use crate::support::for_each_function_def;
use crate::support::issue_at;
use crate::support::to_u32;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

/// python:S1142 — `return` statements per function against
/// `maximumReturnStatements`.
pub(crate) fn check_function_return_counts(
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
            let count = count_own_returns(&function.body);
            let maximum = options.maximum_return_statements;
            if to_u32(count) > maximum {
                issues.push(issue_at(
                    "python:S1142",
                    &format!(
                        "This function has {count} returns or yields, which is more than the \
                         {maximum} allowed."
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
