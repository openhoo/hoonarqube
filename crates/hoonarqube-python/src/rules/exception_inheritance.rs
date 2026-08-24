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

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s5709_requires_exception_base_for_exception_named_classes() {
        assert_eq!(
            findings(&scan("class AppError:\n    pass\n"), "python:S5709").len(),
            1
        );
        for clean in [
            "class AppError(Exception):\n    pass\n",
            "class Plain:\n    pass\n",
        ] {
            assert!(findings(&scan(clean), "python:S5709").is_empty(), "{clean}");
        }
    }
}
