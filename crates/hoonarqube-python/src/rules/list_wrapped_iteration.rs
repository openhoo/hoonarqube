use crate::support::for_each_stmt;
use crate::support::is_call_to;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7504 — list() when iterating ---------------------------------------

pub(crate) fn check_list_wrapped_iteration(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::For(for_stmt) = stmt
            && is_call_to(&for_stmt.iter, "list")
        {
            issues.push(issue_at(
                "python:S7504",
                "Iterate over the iterable directly; wrapping it in 'list()' is unnecessary.",
                for_stmt.iter.range(),
                index,
                source,
            ));
        }
    });
    issues
}
