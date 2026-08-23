use crate::support::for_each_stmt;
use crate::support::is_builtin_exception_base;
use crate::support::issue_at;
use crate::support::looks_like_exception_name;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_exception_inheritance(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::ClassDef(class) = stmt
            && looks_like_exception_name(class.name.as_str())
            && !class.bases().iter().any(is_builtin_exception_base)
        {
            issues.push(issue_at(
                "python:S5709",
                "Make this exception inherit from a built-in exception class.",
                class.name.range(),
                index,
                source,
            ));
        }
    });
    issues
}
