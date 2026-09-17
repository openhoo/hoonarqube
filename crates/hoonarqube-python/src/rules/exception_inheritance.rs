use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_exception_inheritance(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        if let Stmt::ClassDef(class) = stmt
            && looks_like_exception_name(class.name.as_str())
            // Sonar's ExceptionSuperClassDeclarationCheck flags only bases
            // that ARE BaseException/GeneratorExit/KeyboardInterrupt/
            // SystemExit — a custom exception should inherit Exception.
            && class.bases().iter().any(is_too_low_exception_base)
        {
            issues.push(issue_at(
                "python:S5709",
                "Make this exception inherit from a built-in exception class.",
                class.name.range(),
                index,
                source,
            ));
        }
    }
    issues
}

// --- python:S5709 — custom exceptions inherit Exception -----------------------

pub(crate) fn looks_like_exception_name(name: &str) -> bool {
    name.ends_with("Error") || name.ends_with("Warning") || name.ends_with("Exception")
}

fn is_too_low_exception_base(expr: &Expr) -> bool {
    let tail = match expr {
        Expr::Name(name) => Some(name.id.as_str()),
        Expr::Attribute(attribute) => Some(attribute.attr.as_str()),
        _ => None,
    };
    matches!(
        tail,
        Some("BaseException" | "GeneratorExit" | "KeyboardInterrupt" | "SystemExit")
    )
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};
    #[test]
    fn s5709_flags_exception_named_classes_inheriting_too_low() {
        assert_eq!(
            findings(
                &scan("class AppError(BaseException):\n    pass\n"),
                "python:S5709"
            )
            .len(),
            1
        );
        for clean in [
            "class AppError(Exception):\n    pass\n",
            "class AppError:\n    pass\n",
            "class Plain(BaseException):\n    pass\n",
        ] {
            assert!(findings(&scan(clean), "python:S5709").is_empty(), "{clean}");
        }
    }
}
