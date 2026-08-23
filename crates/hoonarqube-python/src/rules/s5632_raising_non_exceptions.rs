use crate::support::for_each_stmt;
use crate::support::is_non_exception_literal;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5632 — raised values derive from BaseException ------------------------

pub(crate) fn check_s5632_raising_non_exceptions(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::Raise(raise) = stmt
            && let Some(exc) = raise.exc.as_ref()
            && is_non_exception_literal(exc)
        {
            issues.push(issue_at(
                "python:S5632",
                "Raise an exception derived from BaseException.",
                exc.range(),
                index,
                source,
            ));
        }
    });
    issues
}
