use crate::support::for_each_stmt;
use crate::support::issue_at;
use crate::support::positional_parameters;
use crate::support::required_special_method_arity;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_special_method_arities(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::FunctionDef(function) = stmt else {
            return;
        };
        let Some(required) = required_special_method_arity(function.name.as_str()) else {
            return;
        };
        if function.name.as_str() == "__exit__"
            || function.parameters.vararg.is_some()
            || positional_parameters(&function.parameters).len() >= required
        {
            return;
        }
        issues.push(issue_at(
            "python:S5722",
            "Fix this special method signature; it is missing required parameters.",
            function.name.range(),
            index,
            source,
        ));
    });
    issues
}
