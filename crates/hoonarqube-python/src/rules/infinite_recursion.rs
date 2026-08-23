use crate::support::for_each_stmt;
use crate::support::issue_at;
use crate::support::straight_line_self_call;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_infinite_recursion(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::FunctionDef(function) = stmt
            && straight_line_self_call(&function.body, function.name.as_str())
        {
            issues.push(issue_at(
                "python:S2190",
                "Add a way to break out of this recursive call.",
                function.name.range(),
                index,
                source,
            ));
        }
    });
    issues
}
