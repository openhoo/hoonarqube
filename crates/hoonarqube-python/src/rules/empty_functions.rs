use crate::support::for_each_function_def;
use crate::support::has_decorator;
use crate::support::issue_at;
use crate::support::placeholder_only_suite;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::StmtFunctionDef;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S1186 — empty functions -------------------------------------------
//
// Functions holding nothing but `pass`/`...` placeholders are flagged.
// `@abstractmethod`/`@overload` stubs are legitimate empty by contract; a
// docstring already fills the function and is not an empty body.

pub(crate) fn check_empty_functions(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut visit = |function: &StmtFunctionDef, _in_class_body: bool| {
        if has_decorator(function, "abstractmethod") || has_decorator(function, "overload") {
            return;
        }
        if placeholder_only_suite(&function.body) {
            issues.push(issue_at(
                "python:S1186",
                "Update this function to remove code, add code, or add documentation.",
                function.name.range(),
                index,
                source,
            ));
        }
    };
    for_each_function_def(parsed.syntax().body.as_slice(), false, &mut visit);
    issues
}
