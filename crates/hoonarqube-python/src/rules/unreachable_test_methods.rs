use crate::support::for_each_stmt;
use crate::support::is_test_case_base;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_unreachable_test_methods(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::ClassDef(class) = stmt else { return };
        if !class.bases().iter().any(is_test_case_base) {
            return;
        }
        for member in &class.body {
            if let Stmt::FunctionDef(function) = member {
                let name = function.name.as_str();
                if name.contains("test") && !name.starts_with("test") {
                    issues.push(issue_at(
                        "python:S5899",
                        "Rename this method to start with 'test' or remove it; test runners will not discover it.",
                        function.name.range(),
                        index,
                        source,
                    ));
                }
            }
        }
    });
    issues
}
