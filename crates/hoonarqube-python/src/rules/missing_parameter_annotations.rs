use crate::AnalyzerOptions;
use crate::support::for_each_stmt;
use crate::support::function_parameters;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_missing_parameter_annotations(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    if !options.require_type_hints {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::FunctionDef(function) = stmt {
            for parameter in function_parameters(function) {
                if parameter.parameter.annotation.is_none() {
                    issues.push(issue_at(
                        "python:S6540",
                        "Annotate this parameter.",
                        parameter.range(),
                        index,
                        source,
                    ));
                }
            }
        }
    });
    issues
}
