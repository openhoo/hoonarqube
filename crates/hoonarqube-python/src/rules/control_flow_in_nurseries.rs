use crate::support::for_each_nursery_block;
use crate::support::for_each_stmt_in_scope;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_control_flow_in_nurseries(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_nursery_block(parsed.syntax().body.as_slice(), &mut |with_stmt| {
        for_each_stmt_in_scope(with_stmt.body.as_slice(), &mut |stmt| {
            if matches!(stmt, Stmt::Return(_) | Stmt::Break(_) | Stmt::Continue(_)) {
                issues.push(issue_at(
                    "python:S7514",
                    "Do not jump out of a nursery block.",
                    stmt.range(),
                    index,
                    source,
                ));
            }
        });
    });
    issues
}
