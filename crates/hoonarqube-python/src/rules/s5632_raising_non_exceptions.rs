use crate::engine::file_context::FileContext;
use crate::support::is_non_exception_literal;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5632 — raised values derive from BaseException ------------------------

pub(crate) fn check_s5632_raising_non_exceptions(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        if let Stmt::Raise(raise) = stmt
            && let Some(exc) = raise.exc.as_ref()
            && is_non_exception_literal(exc)
        {
            issues.push(issue_at(
                "python:S5632",
                "Change this code so that it raises an object deriving from BaseException.",
                raise.range(),
                index,
                source,
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s5632_flags_literal_raises_and_spares_exception_instances() {
        let bad = scan("raise 42\n");
        assert_eq!(findings(&bad, "python:S5632").len(), 1);

        let good = scan("raise ValueError('bad')\n");
        assert!(findings(&good, "python:S5632").is_empty());
    }
}
