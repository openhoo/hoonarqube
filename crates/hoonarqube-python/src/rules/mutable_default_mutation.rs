use crate::support::for_each_stmt;
use crate::support::function_parameters;
use crate::support::is_mutable_default;
use crate::support::is_none_literal;
use crate::support::issue_at;
use crate::support::parameter_is_assigned;
use crate::support::parameter_is_mutated;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_mutable_default_mutation(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let _ = source;
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::FunctionDef(function) = stmt {
            for parameter in function_parameters(function) {
                let Some(default) = parameter.default() else {
                    continue;
                };
                if is_mutable_default(default)
                    && parameter_is_mutated(&function.body, parameter.parameter.name.as_str())
                {
                    issues.push(issue_at(
                        "python:S5717",
                        "Do not mutate this mutable default argument.",
                        default.range(),
                        index,
                        source,
                    ));
                }
                if !is_none_literal(default)
                    && parameter_is_assigned(&function.body, parameter.parameter.name.as_str())
                {
                    issues.push(issue_at(
                        "python:S5717",
                        "Do not assign to this parameter; introduce a local variable.",
                        default.range(),
                        index,
                        source,
                    ));
                }
            }
        }
    });
    issues
}
