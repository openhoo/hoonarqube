use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_exception_inheritance(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class in &file_ctx.classes {
        // Sonar's ExceptionSuperClassDeclarationCheck reports every base
        // argument that IS BaseException/GeneratorExit/KeyboardInterrupt/
        // SystemExit — a custom exception should inherit Exception. There
        // is no class-name check: any class deriving from those bases is
        // flagged, and the issue is reported on the offending base.
        for base in class.bases() {
            if let Some(name) = too_low_exception_base_name(base) {
                issues.push(issue_at(
                    "python:S5709",
                    &format!("Derive this class from \"Exception\" instead of \"{name}\"."),
                    base.range(),
                    index,
                    source,
                ));
            }
        }
    }
    issues
}

// --- python:S5709 — custom exceptions inherit Exception -----------------------

fn too_low_exception_base_name(expr: &Expr) -> Option<&str> {
    let tail = match expr {
        Expr::Name(name) => name.id.as_str(),
        Expr::Attribute(attribute) => attribute.attr.as_str(),
        _ => return None,
    };
    matches!(
        tail,
        "BaseException" | "GeneratorExit" | "KeyboardInterrupt" | "SystemExit"
    )
    .then_some(tail)
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, pos, scan};

    #[test]
    fn s5709_flags_classes_inheriting_too_low() {
        // Sonar reports each forbidden base argument, not the class name
        // (issue #612).
        let report = scan("class AppError(BaseException):\n    pass\n");
        let flagged = findings(&report, "python:S5709");
        assert_eq!(flagged.len(), 1);
        assert_eq!(
            flagged[0].message,
            "Derive this class from \"Exception\" instead of \"BaseException\"."
        );
        assert_eq!(flagged[0].range.start, pos(1, 15));
        assert_eq!(flagged[0].range.end, pos(1, 28));

        for base in ["GeneratorExit", "KeyboardInterrupt", "SystemExit"] {
            let source = format!("class AppError({base}):\n    pass\n");
            assert_eq!(
                findings(&scan(&source), "python:S5709").len(),
                1,
                "{source}"
            );
        }
        // One issue per offending base argument.
        let report = scan("class AppError(BaseException, SystemExit):\n    pass\n");
        let both = findings(&report, "python:S5709");
        assert_eq!(both.len(), 2);
    }

    #[test]
    fn s5709_flags_unnamed_and_nested_classes() {
        // No class-name gate: Sonar flags any class deriving from the
        // forbidden bases, including names without an exception suffix
        // and classes nested inside function bodies.
        for flagged in [
            "class Plain(BaseException):\n    pass\n",
            "def f():\n    class Inner(KeyboardInterrupt):\n        pass\n",
        ] {
            assert_eq!(
                findings(&scan(flagged), "python:S5709").len(),
                1,
                "{flagged}"
            );
        }
    }

    #[test]
    fn s5709_accepts_exception_and_other_bases() {
        for clean in [
            "class AppError(Exception):\n    pass\n",
            "class AppError:\n    pass\n",
            // The pinned django/django false positive: a custom exception
            // subclass is not one of the four forbidden bases.
            "class InvalidCacheBackendError(ImproperlyConfigured):\n    pass\n",
            "class Plain:\n    pass\n",
        ] {
            assert!(findings(&scan(clean), "python:S5709").is_empty(), "{clean}");
        }
    }
}
