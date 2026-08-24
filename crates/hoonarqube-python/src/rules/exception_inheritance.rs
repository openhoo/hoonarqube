use crate::support::for_each_stmt;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
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

// --- migrated from support/mod.rs (S5709) ---
// --- python:S5709 — custom exceptions inherit Exception -----------------------

pub(crate) fn looks_like_exception_name(name: &str) -> bool {
    name.ends_with("Error") || name.ends_with("Warning") || name.ends_with("Exception")
}

pub(crate) fn is_builtin_exception_base(expr: &Expr) -> bool {
    let tail = match expr {
        Expr::Name(name) => Some(name.id.as_str()),
        Expr::Attribute(attribute) => Some(attribute.attr.as_str()),
        _ => None,
    };
    matches!(tail, Some(base) if base == "Exception" || base == "BaseException" || looks_like_exception_name(base))
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
