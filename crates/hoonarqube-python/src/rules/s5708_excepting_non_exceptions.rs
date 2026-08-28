use crate::engine::file_context::FileContext;
use crate::support::is_non_exception_literal;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ExceptHandler;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5708 — caught values derive from BaseException ------------------------

pub(crate) fn check_s5708_excepting_non_exceptions(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        if let Stmt::Try(try_) = stmt {
            for handler in &try_.handlers {
                let ExceptHandler::ExceptHandler(inner) = handler;
                if let Some(handled) = inner.type_.as_ref()
                    && is_non_exception_literal(handled)
                {
                    issues.push(issue_at(
                        "python:S5708",
                        "Change this expression to be a class deriving from BaseException or a tuple of such classes.",
                        handled.range(),
                        index,
                        source,
                    ));
                }
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s5708_flags_literal_except_targets() {
        let bad = scan("try:\n    work()\nexcept 42:\n    recover()\n");
        assert_eq!(findings(&bad, "python:S5708").len(), 1);

        let good = scan("try:\n    work()\nexcept ValueError:\n    recover()\n");
        assert!(findings(&good, "python:S5708").is_empty());
    }
}
