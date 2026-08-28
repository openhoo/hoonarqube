use crate::engine::file_context::FileContext;
use crate::support::is_non_exception_literal;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5707 — "__cause__" must be an exception or None -----------------------

pub(crate) fn check_s5707_raise_from_non_exception(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        if let Stmt::Raise(raise) = stmt
            && let Some(cause) = raise.cause.as_ref()
            && is_non_exception_literal(cause)
        {
            issues.push(issue_at(
                "python:S5707",
                "Replace this expression with an exception or None",
                cause.range(),
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
    fn s5707_flags_non_exception_raise_causes() {
        let bad = scan("raise ValueError('bad') from 42\n");
        assert_eq!(findings(&bad, "python:S5707").len(), 1);

        let good = scan("raise ValueError('bad') from KeyError('cause')\n");
        assert!(findings(&good, "python:S5707").is_empty());
    }
}
